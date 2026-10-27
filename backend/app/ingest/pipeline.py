"""Batching event sink: device resolution, idempotent dedupe, ClickHouse insert, ingest health stats."""
import asyncio
import hashlib
import ipaddress
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.ch_schema import EVENT_COLUMNS
from ..db.models import Firewall, IngestStat, LogSource
from ..netguard import resolve
from ..db.pg import session_factory
from .normalize import normalize
from .panos import PARSER_VERSION as PANOS_PARSER, detect as panos_detect, parse as panos_parse
from .parser import ParseError, parse_kv

log = logging.getLogger("ingest")
SOURCE_MISMATCH: dict = {"id": None, "mismatch": True}  # sentinel: device fields name a firewall the sender is not


async def _resolve_name(host: str | None) -> list[str]:
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        pass
    return await resolve(host)


def panos_offset(date: str, time: str, tz: str) -> str:
    """'+0530'-style offset of the firewall's log time zone at that local time (PAN-OS logs carry no offset)."""
    from zoneinfo import ZoneInfo
    try:
        local = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo(tz))
    except (ValueError, KeyError):
        return "+0000"
    off = local.utcoffset() or timedelta(0)
    mins = int(off.total_seconds() // 60)
    return f"{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}{abs(mins) % 60:02d}"


class DeviceRegistry:
    """Maps FortiGate devid (serial), devname or syslog source IP to a registered firewall."""

    def __init__(self):
        self.by_serial: dict[str, dict] = {}
        self.by_name: dict[str, dict] = {}
        self.by_ip: dict[str, dict] = {}
        self.ips_of: dict[int, set[str]] = {}
        self.generic_by_ip: dict[str, dict] = {}  # non-FortiGate sources (Windows / CEF / syslog) by sender IP

    async def refresh(self) -> None:
        async with session_factory()() as s:
            rows = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True)))).scalars().all()
            gen = (await s.execute(select(LogSource).where(LogSource.enabled.is_(True)))).scalars().all()
        self.generic_by_ip = {ip: {"id": g.id, "name": g.name, "kind": g.kind, "site": g.site} for g in gen for ip in (g.source_ips or [])}
        fws = [{"id": f.id, "name": f.name, "site": f.site, "serial": f.serial, "hostname": f.hostname,
                "host": f.host, "syslog_source_ips": f.syslog_source_ips or [], "is_demo": f.is_demo,
                "vendor": f.vendor, "log_tz": f.log_tz} for f in rows]
        for fw in fws:  # firewalls registered by DNS name: accept syslog from the addresses that name resolves to
            fw["resolved_ips"] = await _resolve_name(fw["host"])
        self.load(fws)

    def load(self, fws: list[dict]) -> None:
        self.by_serial, self.by_name, self.by_ip, self.ips_of = {}, {}, {}, {}
        for fw in fws:
            if fw.get("serial"):
                self.by_serial[fw["serial"]] = fw
            for n in (fw.get("hostname"), fw.get("name")):
                if n:
                    self.by_name[n] = fw
            ips = self.ips_of.setdefault(fw["id"], set())
            for ip in [fw.get("host"), *fw.get("syslog_source_ips", []), *fw.get("resolved_ips", [])]:
                if ip:
                    self.by_ip[ip] = fw
                    ips.add(ip)

    def resolve(self, fields: dict, peer_ip: str | None) -> dict | None:
        """devid/devname are text inside the message, so for network syslog (peer_ip set) the sender address must
        also belong to that firewall; otherwise anyone who can reach the port could inject events in its name.
        Returns SOURCE_MISMATCH when the named firewall exists but the sender is not one of its addresses."""
        named = self.by_serial.get(fields.get("devid", "")) or self.by_name.get(fields.get("devname", ""))
        if not peer_ip:
            return named
        if named is None:
            return self.by_ip.get(peer_ip)
        if peer_ip in self.ips_of.get(named["id"], ()) or get_settings().syslog_trust_device_fields:
            return named
        return SOURCE_MISMATCH


class EventSink:
    def __init__(self, ch: ClickHouse, registry: DeviceRegistry, *, batch_size: int | None = None,
                 dedupe_capacity: int = 200_000, enricher=None, stats_hook=None):
        s = get_settings()
        self.stats_hook = stats_hook  # parser worker processes hand stats to the receiver, which persists them once
        self.ch = ch
        self.registry = registry
        self.enricher = enricher
        self.batch_size = batch_size or s.syslog_batch_size
        self.allow_unknown = s.syslog_allow_unknown_devices
        self.buffer: list[dict] = []
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._cap = dedupe_capacity
        self._lock = asyncio.Lock()
        self.stats: dict[tuple[int, str], dict] = {}
        self.counters = {"received": 0, "parsed": 0, "duplicates": 0, "unknown_device": 0, "source_mismatch": 0, "parse_errors": 0, "inserted": 0}

    def _stat(self, fw_id: int, source: str) -> dict:
        return self.stats.setdefault((fw_id, source), {"events": 0, "errors": 0, "last_event": None, "last_error": None})

    def _is_dup(self, eid: str) -> bool:
        if eid in self._seen:
            self._seen.move_to_end(eid)
            return True
        self._seen[eid] = None
        if len(self._seen) > self._cap:
            self._seen.popitem(last=False)
        return False

    def add_fields(self, fields: dict, *, source: str, raw: str | None, peer_ip: str | None = None,
                   firewall: dict | None = None, all_str: bool = False) -> dict | None:
        self.counters["received"] += 1
        fw = firewall or self.registry.resolve(fields, peer_ip)
        if fw is SOURCE_MISMATCH:
            self.counters["source_mismatch"] += 1
            return None
        if fw is None and not self.allow_unknown:
            self.counters["unknown_device"] += 1
            return None
        pan = fields.pop("_pan", None)
        if pan:
            fields.pop("_panlog", None)
            fields["tz"] = panos_offset(fields.get("date", ""), fields.get("time", ""), (fw or {}).get("log_tz") or "UTC")
        ev = normalize(fields, source=source, raw=raw, firewall=fw, all_str=all_str)
        if pan:
            ev["parser_version"] = PANOS_PARSER
            ev["event_id"] = hashlib.sha256(f"{fields.get('devid', '')}|{raw}".encode()).hexdigest()[:32]
        if self.enricher is not None:
            self.enricher.apply(ev)
        self.counters["parsed"] += 1
        if self._is_dup(ev["event_id"]):
            self.counters["duplicates"] += 1
            return None
        self.buffer.append(ev)
        st = self._stat(ev["firewall_id"], source)
        st["events"] += 1
        if st["last_event"] is None or ev["event_time"] > st["last_event"]:
            st["last_event"] = ev["event_time"]
        return ev

    def add_line(self, line: str, *, source: str = "syslog", peer_ip: str | None = None) -> dict | None:
        gen = self.registry.generic_by_ip.get(peer_ip or "") if peer_ip else None
        if gen is not None:
            return self._add_generic(gen, line, source)
        pan = panos_detect(line)
        if pan is not None:  # Palo Alto PAN-OS CSV record
            fields = panos_parse(*pan)
            return self.add_fields(fields, source=source, raw=line.strip(), peer_ip=peer_ip)
        try:
            fields = parse_kv(line)
        except ParseError as e:
            self.counters["received"] += 1
            self.counters["parse_errors"] += 1
            fw = self.registry.by_ip.get(peer_ip or "")
            if fw:
                st = self._stat(fw["id"], source)
                st["errors"] += 1
                st["last_error"] = str(e)
            return None
        return self.add_fields(fields, source=source, raw=line.strip(), peer_ip=peer_ip, all_str=True)

    def _add_generic(self, src: dict, line: str, source: str) -> dict | None:
        from .generic import parse
        self.counters["received"] += 1
        try:
            ev = parse(src, line)
        except Exception as e:  # a malformed line from a third-party sender must never stop ingestion
            self.counters["parse_errors"] += 1
            log.debug("generic parse failed for %s: %s", src["name"], e)
            return None
        if ev is None:
            self.counters["parse_errors"] += 1
            return None
        if self.enricher is not None:
            self.enricher.apply(ev)
        self.counters["parsed"] += 1
        if self._is_dup(ev["event_id"]):
            self.counters["duplicates"] += 1
            return None
        self.buffer.append(ev)
        st = self._stat(ev["firewall_id"], source)
        st["events"] += 1
        if st["last_event"] is None or ev["event_time"] > st["last_event"]:
            st["last_event"] = ev["event_time"]
        return ev

    def should_flush(self) -> bool:
        return len(self.buffer) >= self.batch_size

    async def flush(self) -> int:
        async with self._lock:
            batch, self.buffer = self.buffer, []
            stats, self.stats = self.stats, {}
            if batch:
                try:
                    await self.ch.ainsert("events", batch, EVENT_COLUMNS)
                except Exception:
                    log.exception("clickhouse insert failed; re-queueing %d events", len(batch))
                    self.buffer = batch + self.buffer  # retry on next flush; dedupe cache prevents double counting
                    for k, v in stats.items():
                        self.stats.setdefault(k, v)
                    return 0
                self.counters["inserted"] += len(batch)
            if stats:
                if self.stats_hook is not None:
                    self.stats_hook(stats)
                else:
                    await persist_stats(stats)
            return len(batch)


def merge_stats(into: dict, stats: dict) -> None:
    """Fold one flush's per-(firewall, source) stats into an accumulator."""
    for k, st in stats.items():
        cur = into.get(k)
        if cur is None:
            into[k] = dict(st)
            continue
        cur["events"] += st["events"]
        cur["errors"] += st["errors"]
        if st["last_event"] and (cur["last_event"] is None or st["last_event"] > cur["last_event"]):
            cur["last_event"] = st["last_event"]
        cur["last_error"] = st["last_error"] or cur["last_error"]


async def persist_stats(stats: dict) -> None:
    now = datetime.now(timezone.utc)
    try:
        async with session_factory()() as s:
            from .generic import SOURCE_ID_BASE
            for (fw_id, source), st in stats.items():
                if fw_id == 0:
                    continue
                if fw_id >= SOURCE_ID_BASE:  # generic log source: counters live on log_sources
                    src = await s.get(LogSource, fw_id - SOURCE_ID_BASE)
                    if src is not None:
                        src.events_total = (src.events_total or 0) + st["events"]
                        if st["last_event"]:
                            src.last_event_at = st["last_event"]
                    continue
                row = await s.get(IngestStat, (fw_id, source))
                if row is None:
                    row = IngestStat(firewall_id=fw_id, source=source, events_total=0, parse_errors=0)
                    s.add(row)
                row.events_total = (row.events_total or 0) + st["events"]
                row.parse_errors = (row.parse_errors or 0) + st["errors"]
                if st["events"]:
                    row.last_ingest_time = now
                if st["last_event"]:
                    prev = row.last_event_time
                    if prev is not None and prev.tzinfo is None:
                        prev = prev.replace(tzinfo=timezone.utc)
                    if prev is None or st["last_event"] > prev:
                        row.last_event_time = st["last_event"]
                    row.lag_seconds = max(0.0, (now - st["last_event"]).total_seconds())
                if st["last_error"]:
                    row.last_error = st["last_error"]
            await s.commit()
    except Exception:
        log.exception("failed to persist ingest stats")
