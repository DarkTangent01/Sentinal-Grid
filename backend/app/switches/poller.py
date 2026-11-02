"""Switch polling pipeline: claim → connect / identify → collect groups → normalise → rates → store → events.

* A switch is claimed with a database lease (UPDATE ... WHERE lease expired), so two worker replicas never poll the same
  switch at once, and an in-process set prevents duplicate jobs inside one worker.
* Concurrency is bounded globally (SWITCH_MAX_CONCURRENT_POLLS) and per switch (one SNMP request in flight).
* Every metric group runs in isolation: a failing or timing-out group is recorded and the others still run; a failing
  switch never blocks the others.
* Reachability is damped: DOWN after 2 consecutive failed polls; wrong SNMPv3 credentials are reported as auth_failed
  immediately (an unreachable switch and a credential problem need different fixes).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import (Switch, SwitchCredential, SwitchEvent, SwitchInterface, SwitchMac, SwitchNeighbor, SwitchNetwork, SwitchPollRun,
                         SwitchVlan)
from ..netguard import DestinationError, check_ip
from ..security import TokenCipher
from . import collect as C
from .collect import port_key
from .rates import LAG_TYPE, PHYSICAL_TYPES, flag_names, interface_rates, speed_of
from ..wireless.collect import COLLECTORS as W_COLLECTORS
from .registry import GROUPS, Outcome, coverage, merge_capabilities
from .snmp import Credentials, PysnmpClient, SnmpError

log = logging.getLogger("switches")
ORDER = ["system", "inventory", "interfaces", "cpu_memory", "environment", "stack", "poe", "lacp", "neighbors", "vlans", "stp", "mac_table", "routing", "storage",
         "vendor_health", "custom", "wireless_ap", "wireless_radio", "wireless_radio_rf", "wireless_wlan", "wireless_client", "wireless_ap_cdp",
         "wireless_radio_meta", "wireless_rf_neighbors"]
FAST = {"system", "interfaces", "cpu_memory"}   # follow the switch's poll interval
DOWN_AFTER = 2
METRIC_COLS = ["ts", "switch_id", "metric", "component", "value"]
IF_COLS = ["ts", "switch_id", "ifindex", "interval_s", "rx_bps", "tx_bps", "rx_util", "tx_util", "rx_pps", "tx_pps", "in_errors",
           "out_errors", "in_discards", "out_discards", "crc", "oper", "admin", "flags"]
_inflight: set[int] = set()
_background: set[asyncio.Task] = set()      # controller polls running beyond the current pass (references kept until done)


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ credentials / client
def seal_secret(data: dict) -> str:
    data = {k: v for k, v in data.items() if v}
    return TokenCipher().encrypt(json.dumps(data)) if data else ""


def credentials_of(cred: SwitchCredential) -> Credentials:
    secret = json.loads(TokenCipher().decrypt(cred.secret_ciphertext)) if cred.secret_ciphertext else {}
    return Credentials(version=cred.version, community=secret.get("community", ""), username=cred.username,
                       auth_protocol=cred.auth_protocol, auth_key=secret.get("auth_key", ""), priv_protocol=cred.priv_protocol,
                       priv_key=secret.get("priv_key", ""))


def check_version_allowed(version: str) -> None:
    if version == "v2c" and not get_settings().switch_allow_snmpv2c:
        raise SnmpError("config", "SNMPv2c is disabled (community strings travel in clear text). Use SNMPv3 authPriv, or set "
                                  "SWITCH_ALLOW_SNMPV2C=true if v2c is explicitly approved for these switches.")


def validate_address(addr: str, networks: list[SwitchNetwork]) -> str:
    """Management address must be an IP literal (no DNS: nothing to rebind), not loopback / link-local / reserved, and
    inside an authorised management network."""
    try:
        ip = ipaddress.ip_address((addr or "").strip())
    except ValueError:
        raise ValueError("management address must be an IPv4 or IPv6 address")
    try:
        check_ip(ip)
    except DestinationError as e:
        raise ValueError(str(e))
    if not any(ip in ipaddress.ip_network(n.cidr, strict=False) for n in networks):
        raise ValueError(f"{ip} is not inside an authorised management network (Switch Monitoring → Settings → Networks)")
    return str(ip)


def make_client(sw: Switch, cred: SwitchCredential) -> PysnmpClient:
    c = credentials_of(cred)
    check_version_allowed(c.version)
    return PysnmpClient(sw.address, c, port=sw.port or 161, timeout=max(0.5, (sw.timeout_ms or 3000) / 1000),
                        retries=max(0, min(3, sw.retries if sw.retries is not None else 1)))


def is_wlc(sw: Switch) -> bool:
    return (sw.role or "").lower() == "wlc"


def intervals_of(sw: Switch) -> dict[str, int]:
    """Per-group intervals; wireless groups exist only for wireless controllers (role "wlc")."""
    base = max(30, int(sw.poll_interval_seconds or 60))
    out = {}
    for g, d in GROUPS.items():
        if d.get("wlc") and not is_wlc(sw):
            continue
        v = (sw.group_intervals or {}).get(g)
        if v is None:
            v = base if g in FAST else max(d["interval"], base)
        out[g] = int(v) if int(v) == 0 else max(30, int(v))
    out["system"] = base
    return out


# ------------------------------------------------------------------ collection (no persistence): used by polls and tests
async def run_groups(ctx: C.Ctx, groups: list[str], group_timeout: float = 90.0, wireless_group_timeout: float | None = None) -> tuple[dict, dict, set]:
    """Run the given groups in order. Returns (data, group_report, groups_run). Raises SnmpError only for 'system'."""
    funcs = {**C.collectors(ctx.vendor), **W_COLLECTORS}
    data: dict = {}
    report: dict = {}
    ran: set[str] = set()
    timeouts = 0
    for g in [x for x in ORDER if x in groups]:
        if g not in groups:  # dropped after identification (e.g. wireless groups on a non-Cisco device)
            continue
        t0 = time.monotonic()
        if timeouts >= 2:
            report[g] = {"ok": False, "skipped": True, "error": "skipped: the switch stopped answering during this poll"}
            continue
        try:
            res = dict(await asyncio.wait_for(funcs[g](ctx), wireless_group_timeout if wireless_group_timeout and g.startswith("wireless_") else group_timeout))
            inv_ident = res.pop("identity", None)
            data.update(res)
            report[g] = {"ok": True, "duration_ms": int((time.monotonic() - t0) * 1000)}
            if g == "system":
                ident = C.identify(res.get("sys_object_id", ""), res.get("sys_descr", ""), vendor_override=ctx.vendor_override,
                                   family_override=ctx.family_override)
                ctx.product_line = ident.get("product_line", "")
                if ident["vendor"] != ctx.vendor:
                    ctx.vendor = ident["vendor"]
                    funcs = {**C.collectors(ctx.vendor), **W_COLLECTORS}
                if ctx.vendor != "cisco":  # the wireless MIBs are Cisco enterprise MIBs: never requested from other vendors
                    for wg in [x for x in groups if x.startswith("wireless_")]:
                        groups = [x for x in groups if x != wg]
                data["identity"] = {**ident, **{k: v for k, v in (data.get("identity") or {}).items() if v}}
            if g == "inventory":
                ctx.prev["entity_names"] = res.get("entity_names") or {}
                ident = data.get("identity") or {}
                inv = inv_ident or {}
                data["identity"] = {**ident, **{k: v for k, v in inv.items() if v and (k != "firmware" or not ident.get("firmware"))}}
                if inv.get("model") and not ctx.family_override and (not ident.get("family") or ident.get("family") == ident.get("product_line")):
                    data["identity"]["family"] = C.family_of(ctx.vendor, inv["model"]) or ident.get("family", "")
            if g == "interfaces":
                ctx.prev["interfaces"] = res.get("interfaces") or {}
            if g == "vlans":
                ctx.prev["vlans"] = res.get("vlans") or {}
            if g == "wireless_radio":
                ctx.prev["wireless_radios"] = res.get("wireless_radios") or {}
            ran.add(g)
        except (SnmpError, asyncio.TimeoutError) as e:
            if g == "system":
                raise e if isinstance(e, SnmpError) else SnmpError("timeout", "system group timed out")
            limit = wireless_group_timeout if wireless_group_timeout and g.startswith("wireless_") else group_timeout
            msg = e.message if isinstance(e, SnmpError) else f"group timed out after {limit:.0f}s"
            kind = e.kind if isinstance(e, SnmpError) else "timeout"
            timeouts += kind == "timeout"
            for k in C.GROUP_METRICS.get(g, []):
                ctx.outcome.error(k, msg)
            ran.add(g)
            report[g] = {"ok": False, "error": msg, "kind": kind, "duration_ms": int((time.monotonic() - t0) * 1000)}
        except Exception as e:  # a parser defect in one group must not stop the poll
            log.exception("switch group %s failed", g)
            for k in C.GROUP_METRICS.get(g, []):
                ctx.outcome.error(k, f"internal error: {type(e).__name__}")
            ran.add(g)
            report[g] = {"ok": False, "error": f"internal error: {type(e).__name__}", "duration_ms": int((time.monotonic() - t0) * 1000)}
    return data, report, ran


# ------------------------------------------------------------------ poll one switch (persisting)
class _Events:
    def __init__(self, s: AsyncSession, sw: Switch, now: datetime):
        self.s, self.sw, self.now, self.items = s, sw, now, []

    def add(self, kind: str, severity: str, component: str, detail: str, **data):
        e = SwitchEvent(switch_id=self.sw.id, at=self.now, kind=kind, severity=severity, component=component[:255], detail=detail,
                        data=json.loads(json.dumps(data, default=str)))
        self.s.add(e)
        self.items.append(e)


async def poll_switch(s: AsyncSession, ch, sw: Switch, cred: SwitchCredential | None, *, client=None, now: datetime | None = None,
                      kind: str = "poll", force: bool = False) -> dict:
    now = now or datetime.now(timezone.utc)
    st = get_settings()
    t0 = time.monotonic()
    ev = _Events(s, sw, now)
    intervals = intervals_of(sw)
    sw._prev_poll_at = sw.last_poll_at
    sw.last_poll_at = now
    metrics: list[dict] = []
    try:
        if cred is None:
            raise SnmpError("config", "no SNMP credential profile assigned")
        nets = (await s.execute(select(SwitchNetwork))).scalars().all()
        try:
            validate_address(sw.address, nets)
        except ValueError as e:
            raise SnmpError("config", str(e))
        client = client or make_client(sw, cred)
        snmp_version = getattr(getattr(client, "creds", None), "version", None) or cred.version
    except SnmpError as e:
        return await _failed(s, ch, sw, ev, e, now, t0, kind, metrics)
    ifrows = {r.ifindex: r for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sw.id))).scalars()}
    vrows = {r.vlan_id: r for r in (await s.execute(select(SwitchVlan).where(SwitchVlan.switch_id == sw.id))).scalars()}
    health = dict(sw.health or {})
    prev = {"interfaces": {r.ifindex: {"ifindex": r.ifindex, "name": r.name, "descr": r.descr, "mac": r.mac} for r in ifrows.values() if r.present},
            "vlans": {v: {} for v, r in vrows.items() if r.present}, "entity_names": {int(k): v for k, v in (health.get("entity_names") or {}).items()},
            "firmware": sw.firmware}
    vendor = sw.vendor_override or (sw.vendor if sw.vendor in ("cisco", "fortinet", "juniper", "ruckus", "generic") else "generic")
    ctx = C.Ctx(client=client, vendor=vendor, outcome=Outcome(), snmp_version=snmp_version, prev=prev,
                max_vlan_contexts=st.switch_max_vlan_contexts, max_macs=st.switch_max_macs, vendor_override=sw.vendor_override or "",
                family_override=sw.family_override or "", product_line=sw.product_line or "")
    from ..snmp_profiles import custom_items_for, disabled_metrics
    ctx.custom_oids = await custom_items_for(s, sw)
    ctx.disabled = await disabled_metrics(s)
    gs = dict(sw.group_state or {})
    due = ["system"]
    for g in ORDER[1:]:
        iv = intervals.get(g, 0)
        if iv == 0:
            continue
        last = _aware((gs.get(g) or {}).get("last_run"))
        if force or last is None or (now - last).total_seconds() >= iv - 5 or sw.vendor == "unknown":
            due.append(g)
    if ctx.disabled:   # a group whose every metric an administrator disabled is not collected at all
        due = [g for g in due if g == "system" or not C.GROUP_METRICS.get(g) or not set(C.GROUP_METRICS[g]) <= ctx.disabled]
    if "mac_table" in due or "stp" in due:
        if vendor == "cisco" and not prev["vlans"] and "vlans" not in due:
            due.append("vlans")
    try:
        data, report, ran = await run_groups(ctx, due, wireless_group_timeout=st.switch_wireless_group_timeout_seconds if is_wlc(sw) else None)
    except SnmpError as e:
        await client.close()
        return await _failed(s, ch, sw, ev, e, now, t0, kind, metrics)
    await client.close()
    # ---- identity / restart / firmware
    ident = data.get("identity") or {}
    if ctx.vendor != sw.vendor:
        if sw.vendor not in ("unknown", ""):
            ev.add("vendor_change", "medium", "system", f"identified as {ctx.vendor} (was {sw.vendor})")
        sw.vendor = ctx.vendor
    ticks = data.get("uptime_ticks")
    if ticks is not None and sw.uptime_ticks is not None and ticks < sw.uptime_ticks and sw.uptime_ticks < 4_200_000_000:
        ev.add("restart", "high", "system", f"switch restarted: uptime went from {_dur(sw.uptime_ticks / 100)} to {_dur(ticks / 100)}",
               previous_uptime_s=sw.uptime_ticks / 100, uptime_s=ticks / 100)
    fw = ident.get("firmware") or ""
    if fw and sw.firmware and fw != sw.firmware:
        ev.add("firmware_change", "medium", "system", f"software version changed from {sw.firmware} to {fw}", old=sw.firmware, new=fw)
    for k in ("family", "model", "serial", "firmware", "os"):
        if ident.get(k):
            setattr(sw, k, str(ident[k])[:128])
    if ident:
        sw.product_line = (ident.get("product_line") or "")[:64]
        sw.device_type = (ident.get("device_type") or "")[:16]
        sw.id_confidence = (ident.get("confidence") or "")[:16]
        health["identity"] = {k: ident.get(k) for k in ("matched_by", "confidence", "enterprise", "override_conflict", "product_line", "device_type")}
    if data.get("engine_id"):
        sw.engine_id = data["engine_id"][:80]
    for k in ("sys_descr", "sys_object_id", "sys_name", "location"):
        if data.get(k) is not None:
            setattr(sw, k, data[k] if k == "sys_descr" else str(data[k])[:255])
    if ticks is not None:
        sw.uptime_ticks = ticks
        metrics.append(_m(now, sw, "switch_uptime_seconds", "", ticks / 100))
    # ---- groups
    if "inventory" in ran and data.get("inventory") is not None:
        health["inventory"] = data["inventory"]
        health["entity_names"] = {str(k): v for k, v in list((data.get("entity_names") or {}).items())[:3000]}
        if ident.get("serials"):
            health["serials"] = ident["serials"]
    if "interfaces" in ran and data.get("interfaces"):
        metrics += await _interfaces(s, ch, sw, ifrows, data["interfaces"], now, ticks, intervals["interfaces"], ev)
    if "cpu_memory" in ran:
        cpu, mem = data.get("cpu"), data.get("memory")
        health["cpu"], health["memory"] = cpu, mem
        sw.cpu_pct = float(cpu["pct"]) if cpu and cpu.get("pct") is not None else None
        sw.mem_pct = float(mem["pct"]) if mem and mem.get("pct") is not None else None
        for c in (cpu or {}).get("cpus", []):
            v = c["pct_1m"] if c["pct_1m"] is not None else c["pct_5m"]
            if v is not None:
                metrics.append(_m(now, sw, "switch_cpu_utilization_percent", c["name"], v))
        for k, v in ((cpu or {}).get("load") or {}).items():
            metrics.append(_m(now, sw, "switch_load_average", k, v))
        if mem:
            metrics.append(_m(now, sw, "switch_memory_utilization_percent", "", mem["pct"]))
            if mem.get("used_bytes") is not None:
                metrics.append(_m(now, sw, "switch_memory_used_bytes", "", mem["used_bytes"]))
    if "environment" in ran and data.get("environment") is not None:
        _environment(sw, health, data["environment"], now, ev, metrics)
    if "vendor_health" in ran:
        _vendor_health(sw, health, data.get("vendor"), now, ev, metrics)
    if "custom" in ran and data.get("custom") is not None:
        _custom(sw, health, data["custom"], now, metrics)
    if "storage" in ran and data.get("storage") is not None:
        health["storage"] = data["storage"]
        for v in data["storage"]:
            metrics.append(_m(now, sw, "switch_storage_used_percent", v["name"][:96], v["pct"]))
    if "stack" in ran:
        _stack(health, data.get("stack"), ev)
    if "poe" in ran:
        _poe(sw, health, data.get("poe"), ifrows, now, ev, metrics)
    if "lacp" in ran:
        _lacp(health, data.get("lacp"), ifrows, ev)
    if "vlans" in ran and data.get("vlans") is not None:
        await _vlans(s, sw, vrows, ifrows, data["vlans"], data.get("port_vlans") or {}, now, ev, metrics)
    if "stp" in ran:
        _stp(health, data.get("stp"), ifrows, now, sw, ev, metrics)
    if "mac_table" in ran and data.get("macs") is not None:
        await _macs(s, sw, ifrows, data["macs"], now, ev, metrics, bool(data.get("mac_truncated")))
    if "routing" in ran:
        _routing(health, data.get("routing"), ev, metrics, now, sw)
    if "neighbors" in ran and data.get("neighbors") is not None:
        await _neighbors(s, sw, data["neighbors"], now, ev, metrics)
    if is_wlc(sw) and any(g.startswith("wireless_") for g in ran):
        from ..wireless.store import persist as wireless_persist
        await wireless_persist(s, ch, sw, data, ran, now, intervals, health)
    # ---- capabilities, state, history
    for g in ran:
        gs[g] = {"last_run": now.isoformat(), **report.get(g, {})}
    sw.group_state = gs
    sw.capabilities = merge_capabilities(sw.capabilities, ctx.outcome, ran, now, sw.vendor, intervals)
    for k in ctx.disabled & set(sw.capabilities):
        sw.capabilities[k] = {**sw.capabilities[k], "last_result": "not_configured", "reason": "disabled by an administrator"}
    cov = coverage(sw.capabilities, now, intervals)
    sw.coverage_pct = cov["percent"]
    health["coverage"] = cov
    sw.health = health
    if sw.state != "up":
        since = _aware(sw.state_since)
        if sw.state in ("down", "auth_failed"):
            ev.add("reachable", "informational", "system", f"switch answering again after {_dur((now - since).total_seconds()) if since else 'an outage'}"
                   + (f" ({sw.state.replace('_', ' ')})" if sw.state == "auth_failed" else ""),
                   previous_state=sw.state, outage_s=(now - since).total_seconds() if since else None)
        sw.state, sw.state_since = "up", now
    sw.fail_streak = 0
    sw.backoff_until = None
    sw.last_success_at = now
    failed = {g: r["error"] for g, r in report.items() if not r.get("ok")}
    sw.last_error = "; ".join(f"{g}: {e}" for g, e in failed.items())[:2000]
    sw.last_error_kind = "partial" if failed else ""
    dur = int((time.monotonic() - t0) * 1000)
    sw.poll_duration_ms = dur
    metrics += [_m(now, sw, "switch_up", "", 1), _m(now, sw, "switch_poll_duration_seconds", "", dur / 1000),
                _m(now, sw, "switch_metric_coverage_percent", "", cov["percent"] if cov["percent"] is not None else 0)]
    requests = getattr(client, "requests", 0)
    s.add(SwitchPollRun(switch_id=sw.id, started_at=now, duration_ms=dur, ok=not failed, kind=kind, requests=requests, groups=report,
                        error=sw.last_error))
    await s.commit()
    await _insert(ch, "switch_metrics", metrics, METRIC_COLS)
    return {"ok": True, "groups": report, "events": [e.kind for e in ev.items], "duration_ms": dur, "requests": requests}


def backoff_seconds(fail_streak: int, interval: int, kind: str) -> int:
    """Delay before the next poll of a failing device: normal cadence for the first DOWN_AFTER failures (so an outage is
    confirmed quickly), then doubling up to 15 minutes. Wrong credentials back off from the first failure."""
    first = 1 if kind == "auth" else DOWN_AFTER
    if kind == "config" or fail_streak < first:
        return 0
    return int(min(900, max(30, interval) * 2 ** (fail_streak - first)))


async def _failed(s, ch, sw, ev: _Events, e: SnmpError, now, t0, kind, metrics) -> dict:
    sw.last_error, sw.last_error_kind = e.message[:2000], e.kind
    prev_poll = _aware(sw.last_success_at) if (sw.fail_streak or 0) == 0 else None
    sw.fail_streak = (sw.fail_streak or 0) + 1
    interval = max(30, sw.poll_interval_seconds or 60)
    back = backoff_seconds(sw.fail_streak, interval, e.kind) if kind == "poll" else 0
    sw.backoff_until = now + timedelta(seconds=back) if back else None
    since = _aware(sw.state_since)
    if e.kind == "auth" and sw.state != "auth_failed":
        ev.add("auth_failure", "high", "snmp", f"SNMP credentials rejected: {e.message}")
        sw.state, sw.state_since = "auth_failed", now
    elif e.kind == "timeout" and sw.fail_streak >= DOWN_AFTER and sw.state != "down":
        ev.add("unreachable", "high", "system", f"no SNMP response for {sw.fail_streak} consecutive polls ({e.message})",
               previous_state=sw.state, previous_duration_s=(now - since).total_seconds() if since else None)
        sw.state, sw.state_since = "down", now
    elif e.kind in ("config", "protocol") and sw.state not in ("unknown",) and sw.fail_streak == 1:
        ev.add("poll_error", "medium", "snmp", e.message)
    dur = int((time.monotonic() - t0) * 1000)
    sw.poll_duration_ms = dur
    s.add(SwitchPollRun(switch_id=sw.id, started_at=now, duration_ms=dur, ok=False, kind=kind, groups={}, error=f"{e.kind}: {e.message}"[:2000]))
    await s.commit()
    if e.kind != "config":
        # one "down" sample per poll interval since the last attempt, so backing off never makes an outage look shorter
        last = _aware(getattr(sw, "_prev_poll_at", None)) or prev_poll
        gap = int((now - last).total_seconds() // interval) - 1 if last and kind == "poll" else 0
        zeros = [_m(now - timedelta(seconds=interval * i), sw, "switch_up", "", 0) for i in range(0, 1 + max(0, min(gap, 30)))]
        await _insert(ch, "switch_metrics", metrics + zeros, METRIC_COLS)
    return {"ok": False, "error": e.message, "kind": e.kind, "events": [x.kind for x in ev.items], "duration_ms": dur}


async def _insert(ch, table, rows, cols):
    if not rows or ch is None:
        return
    try:
        await ch.ainsert(table, rows, cols)
    except Exception:
        log.exception("clickhouse insert into %s failed", table)


def _m(now, sw, metric, component, value) -> dict:
    return {"ts": now.replace(microsecond=0), "switch_id": sw.id, "metric": metric, "component": str(component)[:96], "value": float(value)}


def _dur(seconds: float) -> str:
    s = int(seconds or 0)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m {s}s"


def if_kind(name: str, if_type: int | None) -> str:
    if if_type == LAG_TYPE or re.match(r"(?i)^(port-channel|po\d|lag|lg\d)", name or ""):
        return "lag"
    if if_type == 136 or re.match(r"(?i)^(vlan\s?\d+|ve\s?\d+)$", name or ""):
        return "svi"
    if if_type in PHYSICAL_TYPES:
        return "physical"
    return "virtual"


def is_uplink(r: SwitchInterface) -> bool:
    return r.kind == "lag" or r.mode == "trunk" or r.lag_ifindex is not None or bool(re.search(r"(?i)uplink|core|dist|trunk|to[-_ ]", r.alias or ""))


async def _interfaces(s, ch, sw, rows: dict, ifaces: dict, now, ticks, interval, ev: _Events) -> list[dict]:
    if_samples, out_metrics = [], []
    max_gap = max(3 * interval, interval + 120)
    seen = set()
    for ifx, d in ifaces.items():
        seen.add(ifx)
        r = rows.get(ifx)
        if r is None:
            r = SwitchInterface(switch_id=sw.id, ifindex=ifx, first_seen=now, counters={})
            s.add(r)
            rows[ifx] = r
        speed, src = speed_of(d.get("high_speed"), d.get("if_speed"))
        cur = {"name": d["name"], "type": d.get("type"), "oper": d["oper"], "speed_bps": speed, "disc": d.get("disc"), "hc": d.get("hc"), "c": d["c"]}
        pc = r.counters or {}
        prev_t = _aware(pc.get("t"))
        elapsed = (now - prev_t).total_seconds() if prev_t else 0
        rates = interface_rates(pc if pc.get("c") else None, cur, elapsed=elapsed, uptime_prev=pc.get("uptime"), uptime_cur=ticks, max_gap=max_gap)
        kind = if_kind(d["name"], d.get("type"))
        label = d["name"] + (f" ({d['alias']})" if d.get("alias") else "")
        if r.oper in ("up", "down") and d["oper"] in ("up", "down", "lower_layer_down") and r.oper != d["oper"] and r.admin == "up" == d["admin"]:
            new = "up" if d["oper"] == "up" else "down"
            if new != r.oper:
                ev.add(f"port_{new}", "low" if not is_uplink(r) else "medium", label, f"{d['name']} went {new}" + (f" ({d['alias']})" if d.get('alias') else ""),
                       ifindex=ifx, name=d["name"], uplink=is_uplink(r), if_kind=kind)
                r.last_change_at = now
        elif (r.oper == d["oper"] == "up" and pc.get("last_change") is not None and d.get("last_change_ticks") is not None
              and d["last_change_ticks"] != pc.get("last_change") and ticks is not None and (pc.get("uptime") or 0) <= ticks):
            ev.add("port_flap", "low" if not is_uplink(r) else "medium", label, f"{d['name']} changed state between polls (down and up again)",
                   ifindex=ifx, name=d["name"], uplink=is_uplink(r))
            r.last_change_at = now
        if r.admin and r.admin != d["admin"] and r.admin in ("up", "down"):
            ev.add("port_admin_change", "low", label, f"{d['name']} administratively {d['admin']}", ifindex=ifx, name=d["name"])
        if r.oper == d["oper"] == "up" and r.speed_bps and speed and r.speed_bps != speed and kind == "physical":
            ev.add("speed_change", "low", label, f"{d['name']} speed changed from {_bps(r.speed_bps)} to {_bps(speed)}", ifindex=ifx, old=r.speed_bps, new=speed)
        if r.oper == d["oper"] == "up" and r.duplex in ("half", "full") and d.get("duplex") in ("half", "full") and r.duplex != d["duplex"]:
            ev.add("duplex_change", "medium" if d["duplex"] == "half" else "low", label, f"{d['name']} duplex changed from {r.duplex} to {d['duplex']}",
                   ifindex=ifx, old=r.duplex, new=d["duplex"])
        r.name, r.descr, r.alias = d["name"][:128], d.get("descr", "")[:255], d.get("alias", "")[:255]
        r.if_type, r.mtu, r.speed_bps, r.speed_source = d.get("type"), d.get("mtu"), speed, src
        r.admin, r.oper, r.duplex, r.mac, r.kind = d["admin"], d["oper"], d.get("duplex") or r.duplex or "", d.get("mac", ""), kind
        r.rx_bps, r.tx_bps, r.rx_util, r.tx_util = rates["rx_bps"], rates["tx_bps"], rates["rx_util"], rates["tx_util"]
        r.in_errors_delta, r.out_errors_delta, r.crc_delta = rates["in_errors"], rates["out_errors"], rates["crc"]
        disc = [x for x in (rates["in_discards"], rates["out_discards"]) if x is not None]
        r.discards_delta = sum(disc) if disc else None
        r.sample_flags, r.sample_note = rates["flags"], (rates.get("reason") or "")[:255]
        r.counters = {**cur, "t": now.isoformat(), "uptime": ticks, "last_change": d.get("last_change_ticks")}
        r.last_sample_at, r.last_seen, r.present = now, now, True
        if_samples.append({"ts": now.replace(microsecond=0), "switch_id": sw.id, "ifindex": ifx, "interval_s": float(elapsed),
                           **{k: rates[k] for k in ("rx_bps", "tx_bps", "rx_util", "tx_util", "rx_pps", "tx_pps", "in_errors", "out_errors",
                                                   "in_discards", "out_discards", "crc")},
                           "oper": 1 if d["oper"] == "up" else 0, "admin": 1 if d["admin"] == "up" else 0, "flags": rates["flags"] & 0xFF})
    for ifx, r in rows.items():
        if ifx not in seen and r.present:
            r.present = False
            ev.add("interface_removed", "low", r.name, f"{r.name} (ifIndex {ifx}) is no longer reported", ifindex=ifx)
    phys = [r for r in rows.values() if r.present and r.kind == "physical"]
    sw.if_total = len(phys)
    sw.if_up = sum(1 for r in phys if r.oper == "up")
    sw.if_errors = sum(1 for r in rows.values() if r.present and ((r.in_errors_delta or 0) + (r.out_errors_delta or 0) + (r.crc_delta or 0)) > 0)
    out_metrics += [_m(now, sw, "switch_interfaces_up", "", sw.if_up), _m(now, sw, "switch_interfaces_total", "", sw.if_total),
                    _m(now, sw, "switch_interfaces_with_errors", "", sw.if_errors)]
    await _insert(ch, "switch_if_samples", if_samples, IF_COLS)
    return out_metrics


def _bps(v) -> str:
    v = float(v or 0)
    for unit, div in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if v >= div:
            return f"{v / div:g} {unit}"
    return f"{v:g} bit/s"


def _vendor_health(sw, health, vh, now, ev: _Events, metrics):
    """Vendor-specific state from the adapter (FortiGate HA / VPN / SD-WAN / sessions, Junos alarms / SRX sessions).
    Alarm transitions become events; the switch_vendor_condition rule alerts on the alarms that are active."""
    old = {a["key"]: a for a in ((health.get("vendor") or {}).get("alarms") or [])}
    if vh is None:
        health.pop("vendor", None)
        return
    new = {a["key"]: a for a in vh.get("alarms") or []}
    for k, a in new.items():
        if k not in old:
            ev.add("vendor_alarm", a["severity"], a["component"], a["detail"], key=k)
    for k, a in old.items():
        if k not in new:
            ev.add("vendor_alarm_cleared", "informational", a["component"], f"cleared: {a['detail']}", key=k)
    if vh.get("sessions") is not None:
        metrics.append(_m(now, sw, "switch_sessions", "", vh["sessions"]))
    tun = vh.get("vpn_tunnels") or []
    if tun:
        metrics.append(_m(now, sw, "switch_vpn_tunnels_up", "", sum(1 for t in tun if t["state"] == "up")))
        metrics.append(_m(now, sw, "switch_vpn_tunnels_down", "", sum(1 for t in tun if t["state"] == "down")))
    for x in vh.get("sdwan") or []:
        comp = f"{x['health_check']}:{x['interface']}"
        for k in ("latency_ms", "jitter_ms", "loss_pct"):
            if x.get(k) is not None:
                metrics.append(_m(now, sw, f"switch_sdwan_{k}", comp, x[k]))
    for x in vh.get("spu") or []:
        if x.get("sessions") is not None:
            metrics.append(_m(now, sw, "switch_sessions", f"SPU {x['index']}", x["sessions"]))
    health["vendor"] = vh


def _custom(sw, health, rows, now, metrics):
    """Custom OID values. Counters become per-second rates from the previous sample (no rate across a reset / wrap)."""
    prev = health.get("custom_prev") or {}
    nxt = {}
    shown = []
    for r in rows:
        key = f"{r['name']}|{r['index']}"
        v = r["value"]
        if r["status"] == "ok" and v is not None and r["value_type"] == "counter":
            nxt[key] = {"v": v, "t": now.isoformat()}
            p = prev.get(key)
            rate = None
            if p:
                dt = (now - datetime.fromisoformat(p["t"])).total_seconds()
                if dt > 0 and v >= p["v"]:
                    rate = (v - p["v"]) / dt
            r = {**r, "rate_per_s": rate}
            if rate is not None:
                metrics.append(_m(now, sw, f"custom:{r['name']}", r["index"], rate))
        elif r["status"] == "ok" and v is not None:
            metrics.append(_m(now, sw, f"custom:{r['name']}", r["index"], v))
        shown.append(r)
    health["custom"] = shown[:500]
    health["custom_prev"] = nxt


def _environment(sw, health, env, now, ev: _Events, metrics):
    old = health.get("environment") or {}
    for kind, label in (("fans", "fan"), ("psus", "power supply")):
        before = {x["name"]: x["state"] for x in old.get(kind, [])}
        for x in env.get(kind, []):
            b = before.get(x["name"])
            if b and b != x["state"]:
                bad = x["state"] not in ("ok", "absent", "unknown")
                ev.add(f"{label.replace(' ', '_')}_{'failure' if bad else 'recovered'}", "high" if bad else "informational", x["name"],
                       f"{label} {x['name']}: {b} → {x['state']}", old=b, new=x["state"])
            metrics.append(_m(now, sw, "switch_fan_ok" if kind == "fans" else "switch_psu_ok", x["name"], 1 if x["state"] == "ok" else 0))
    before_t = {x["name"]: x["state"] for x in old.get("temperatures", [])}
    temps = [x for x in env.get("temperatures", []) if x.get("celsius") is not None]
    for x in temps:
        metrics.append(_m(now, sw, "switch_temperature_celsius", x["name"], x["celsius"]))
        b = before_t.get(x["name"])
        if b and b != x["state"] and x["state"] in ("warning", "critical", "shutdown"):
            ev.add("temperature_alarm", "high", x["name"], f"temperature sensor {x['name']} {x['state']} at {x['celsius']} °C", celsius=x["celsius"])
    sw.temp_max_c = max((x["celsius"] for x in temps), default=None)
    for x in env.get("sensors") or []:
        metrics.append(_m(now, sw, "switch_sensor_value", f"{x['kind']}:{x['name']}"[:96], x["value"]))
    health["environment"] = env


def _stack(health, stack, ev: _Events):
    old = health.get("stack") or {}
    if stack and old:
        before = {str(m["unit"]): m for m in old.get("members", [])}
        now_units = {str(m["unit"]): m for m in stack.get("members", [])}
        for u, m in now_units.items():
            b = before.get(u)
            if b is None:
                ev.add("stack_member_added", "medium", f"unit {u}", f"stack member {u} joined ({m['role']}, {m['state']})")
            elif b.get("healthy") and not m.get("healthy"):
                ev.add("stack_member_failure", "high", f"unit {u}", f"stack member {u} is {m['state']} (was {b['state']})", old=b["state"], new=m["state"])
            elif not b.get("healthy") and m.get("healthy"):
                ev.add("stack_member_recovered", "informational", f"unit {u}", f"stack member {u} is {m['state']} again")
            elif b.get("role") != m.get("role") and "active" in (b.get("role"), m.get("role")):
                ev.add("stack_role_change", "medium", f"unit {u}", f"stack member {u} role {b.get('role')} → {m.get('role')}")
        for u in set(before) - set(now_units):
            ev.add("stack_member_failure", "high", f"unit {u}", f"stack member {u} is no longer reported")
        if old.get("ring_redundant") is True and stack.get("ring_redundant") is False:
            ev.add("stack_ring_broken", "high", "stack", "stack ring is no longer redundant (chain topology)")
    health["stack"] = stack


def _poe(sw, health, poe, ifrows, now, ev: _Events, metrics):
    old = health.get("poe") or {}
    health["poe"] = {k: v for k, v in (poe or {}).items() if k != "ports"} if poe else None
    sw.poe_budget_w = poe.get("budget_w") if poe else None
    sw.poe_used_w = poe.get("used_w") if poe else None
    if not poe:
        return
    for u in poe.get("units", []):
        if u.get("budget_w") is not None:
            metrics.append(_m(now, sw, "switch_poe_budget_watts", f"unit {u['unit']}", u["budget_w"]))
        if u.get("used_w") is not None:
            metrics.append(_m(now, sw, "switch_poe_power_watts", f"unit {u['unit']}", u["used_w"]))
    faults = []
    for p in poe.get("ports", []):
        r = ifrows.get(p.get("ifindex")) if p.get("ifindex") is not None else None
        if r is not None:
            was = (r.poe or {}).get("status")
            r.poe = {k: p.get(k) for k in ("status", "admin", "class", "priority", "power_w", "allocated_w", "key")}
            if was and was != p["status"] and p["status"] in ("fault", "other_fault"):
                faults.append(r.name)
                ev.add("poe_fault", "medium", r.name, f"PoE fault on {r.name} ({p['status']})", ifindex=r.ifindex)
        elif p.get("status") in ("fault", "other_fault") and old:
            faults.append(str(p.get("key")))
    health["poe"]["ports_delivering"] = sum(1 for p in poe.get("ports", []) if p.get("status") == "delivering")
    health["poe"]["ports_fault"] = sum(1 for p in poe.get("ports", []) if p.get("status") in ("fault", "other_fault"))
    health["poe"]["ports_unmapped"] = sum(1 for p in poe.get("ports", []) if p.get("ifindex") is None)


def _lacp(health, lacp, ifrows, ev: _Events):
    old = (health.get("lacp") or {}).get("lags") or {}
    if not lacp:
        health["lacp"] = None
        return
    for r in ifrows.values():
        r.lag_ifindex = None
    lags = {}
    for agg, lag in lacp["lags"].items():
        name = ifrows[agg].name if agg in ifrows else f"LAG {agg}"
        members = []
        for m in lag["members"]:
            r = ifrows.get(m["ifindex"])
            if r is not None:
                r.lag_ifindex = agg
            members.append({"ifindex": m["ifindex"], "name": r.name if r else str(m["ifindex"]), "in_bundle": m.get("in_bundle"),
                            "oper": r.oper if r else "", "protocol": m.get("protocol"),
                            "state": {k: v for k, v in (m.get("actor") or {}).items() if v}})
        up = sum(1 for m in members if m["in_bundle"] or (m["in_bundle"] is None and m["oper"] == "up"))
        lags[str(agg)] = {"ifindex": agg, "name": name, "members": members, "up_members": up, "total_members": len(members),
                          "oper": ifrows[agg].oper if agg in ifrows else ""}
        o = old.get(str(agg))
        if o:
            before = {m["ifindex"]: m for m in o["members"]}
            for m in members:
                b = before.get(m["ifindex"])
                if b and b.get("in_bundle") and m["in_bundle"] is False:
                    ev.add("lacp_member_down", "medium", f"{name}/{m['name']}", f"{m['name']} left the {name} bundle (not collecting/distributing)",
                           lag=name, member=m["name"])
                elif b and b.get("in_bundle") is False and m["in_bundle"]:
                    ev.add("lacp_member_up", "informational", f"{name}/{m['name']}", f"{m['name']} rejoined {name}")
            for ifx in set(before) - {m["ifindex"] for m in members}:
                ev.add("lacp_member_removed", "medium", f"{name}/{before[ifx]['name']}", f"{before[ifx]['name']} is no longer a member of {name}",
                       lag=name, member=before[ifx]["name"])
    health["lacp"] = {"lags": lags}


async def _vlans(s, sw, rows: dict, ifrows, vlans: dict, port_vlans: dict, now, ev: _Events, metrics):
    first = not rows
    for vid, v in vlans.items():
        r = rows.get(vid)
        if r is None:
            r = SwitchVlan(switch_id=sw.id, vlan_id=vid, first_seen=now)
            s.add(r)
            rows[vid] = r
            if not first:
                ev.add("vlan_added", "low", f"VLAN {vid}", f"VLAN {vid} ({v['name'] or 'no name'}) appeared", vlan=vid)
        elif not r.present:
            ev.add("vlan_added", "low", f"VLAN {vid}", f"VLAN {vid} ({v['name'] or 'no name'}) reappeared", vlan=vid)
        elif r.name and v["name"] and r.name != v["name"]:
            ev.add("vlan_renamed", "low", f"VLAN {vid}", f"VLAN {vid} renamed {r.name} → {v['name']}", vlan=vid)
        r.name, r.state, r.tagged, r.untagged = v["name"][:128], v["state"], v["tagged"][:4096], v["untagged"][:4096]
        r.present, r.last_seen = True, now
    for vid, r in rows.items():
        if vid not in vlans and r.present:
            r.present = False
            ev.add("vlan_removed", "medium", f"VLAN {vid}", f"VLAN {vid} ({r.name or 'no name'}) is no longer configured", vlan=vid)
    for ifx, r in ifrows.items():
        pv = port_vlans.get(ifx)
        r.mode = (pv or {}).get("mode", "") if r.kind == "physical" or r.kind == "lag" else ""
        r.access_vlan = (pv or {}).get("access_vlan")
        r.native_vlan = (pv or {}).get("native_vlan")
    metrics.append(_m(now, sw, "switch_vlan_count", "", len(vlans)))


def _stp(health, stp, ifrows, now, sw, ev: _Events, metrics):
    old = health.get("stp") or {}
    if stp is None:
        health["stp"] = None
        return
    names = {ix: r.name for ix, r in ifrows.items()}
    for key, inst in stp["instances"].items():
        o = (old.get("instances") or {}).get(key)
        label = "STP" if key == "default" else f"STP {key.replace('vlan', 'VLAN ')}"
        if o and o.get("root") and inst.get("root") and o["root"] != inst["root"]:
            ev.add("stp_root_change", "high", label, f"{label}: root bridge changed from {o['root']} to {inst['root']}", old=o["root"], new=inst["root"], instance=key)
        if o and o.get("topology_changes") is not None and inst.get("topology_changes") is not None and inst["topology_changes"] > o["topology_changes"]:
            n = inst["topology_changes"] - o["topology_changes"]
            ev.add("stp_topology_change", "low", label, f"{label}: {n} topology change(s) since the last poll", count=n, instance=key)
        if o:
            for ifx, p in inst["ports"].items():
                op = (o.get("ports") or {}).get(str(ifx)) or (o.get("ports") or {}).get(ifx)
                if op and op.get("state") != p["state"] and {op.get("state"), p["state"]} & {"blocking", "broken"}:
                    ev.add("stp_port_state", "medium" if p["state"] in ("blocking", "broken") else "low", f"{label}/{names.get(ifx, ifx)}",
                           f"{label}: {names.get(ifx, ifx)} {op.get('state')} → {p['state']}", instance=key, ifindex=ifx)
        for p in inst["ports"].values():
            p["name"] = names.get(p.get("ifindex"), str(p.get("ifindex") or p.get("bridge_port")))
        inst["ports"] = {str(k): v for k, v in inst["ports"].items()}
        if inst.get("root_port_ifindex"):
            inst["root_port_name"] = names.get(inst["root_port_ifindex"], "")
    if stp.get("topology_changes") is not None:
        metrics.append(_m(now, sw, "switch_stp_topology_changes_total", "", stp["topology_changes"]))
    health["stp"] = stp


async def _macs(s, sw, ifrows, macs: list[dict], now, ev: _Events, metrics, truncated: bool):
    existing = {(r.mac, r.vlan_id): r for r in (await s.execute(select(SwitchMac).where(SwitchMac.switch_id == sw.id))).scalars()}
    first = not existing
    names = {ix: r.name for ix, r in ifrows.items()}
    lag_of = {ix: r.lag_ifindex for ix, r in ifrows.items() if r.lag_ifindex}
    seen, new = set(), 0
    for m in macs:
        key = (m["mac"], int(m.get("vlan") or 0))
        if key in seen:
            continue
        seen.add(key)
        r = existing.get(key)
        port = names.get(m.get("ifindex"), str(m.get("ifindex") or ""))
        if r is None:
            r = SwitchMac(switch_id=sw.id, mac=m["mac"], vlan_id=key[1], first_seen=now, moves=0)
            s.add(r)
            existing[key] = r
            new += 1
        elif r.present and r.ifindex and m.get("ifindex") and r.ifindex != m["ifindex"] \
                and lag_of.get(r.ifindex) != m["ifindex"] and lag_of.get(m["ifindex"]) != r.ifindex \
                and not (lag_of.get(r.ifindex) and lag_of.get(r.ifindex) == lag_of.get(m["ifindex"])):
            r.moves = (r.moves or 0) + 1
            ev.add("mac_move", "low", f"{m['mac']} VLAN {key[1]}", f"{m['mac']} (VLAN {key[1]}) moved from {r.port_name or r.ifindex} to {port}",
                   mac=m["mac"], vlan=key[1], from_port=r.port_name, to_port=port, from_ifindex=r.ifindex, to_ifindex=m["ifindex"])
        r.ifindex, r.port_name, r.status = m.get("ifindex"), port[:128], m.get("status", "")
        r.present, r.last_seen = True, now
    if not truncated:
        for key, r in existing.items():
            if key not in seen and r.present:
                r.present = False
    limit = int((sw.thresholds or {}).get("mac_new_per_poll", 500))
    if not first and new >= limit:
        ev.add("mac_learning_burst", "medium", "MAC table", f"{new} new MAC addresses learned since the last poll (threshold {limit})", new=new)
    await s.execute(delete(SwitchMac).where(SwitchMac.switch_id == sw.id, SwitchMac.present.is_(False),
                                            SwitchMac.last_seen < now - timedelta(days=30)).execution_options(synchronize_session=False))
    metrics.append(_m(now, sw, "switch_mac_table_entries", "", len(seen)))


def _routing(health, routing, ev: _Events, metrics, now, sw):
    old = health.get("routing") or {}
    if routing:
        for kind, key, good in (("ospf", "neighbor", "full"), ("bgp", "peer", "established")):
            before = {x[key]: x["state"] for x in old.get(kind, [])}
            for x in routing.get(kind, []):
                b = before.get(x[key])
                if b and b != x["state"] and good in (b, x["state"]):
                    ev.add(f"{kind}_neighbor_{'up' if x['state'] == good else 'down'}", "informational" if x["state"] == good else "high",
                           f"{kind.upper()} {x[key]}", f"{kind.upper()} neighbor {x[key]}: {b} → {x['state']}", neighbor=x[key])
            for k in set(before) - {x[key] for x in routing.get(kind, [])}:
                if before[k] == good:
                    ev.add(f"{kind}_neighbor_down", "high", f"{kind.upper()} {k}", f"{kind.upper()} neighbor {k} disappeared", neighbor=k)
        if routing.get("route_count") is not None:
            metrics.append(_m(now, sw, "switch_route_count", "", routing["route_count"]))
    health["routing"] = routing


async def _neighbors(s, sw, nbrs: list[dict], now, ev: _Events, metrics):
    rows = {(r.local_ifindex, r.remote_key): r for r in (await s.execute(select(SwitchNeighbor).where(SwitchNeighbor.switch_id == sw.id))).scalars()}
    first = not rows
    seen = set()
    for n in nbrs:
        rkey = ((n.get("sys_name") or "").split(".")[0] or n.get("chassis_id") or n.get("mgmt_ip") or "?").lower()[:255]
        key = (n.get("local_ifindex"), rkey)
        if key in seen:
            continue
        seen.add(key)
        r = rows.get(key)
        label = f"{n.get('local_port')} → {n.get('sys_name') or n.get('chassis_id')} {n.get('port_id') or ''}".strip()
        if r is None:
            r = SwitchNeighbor(switch_id=sw.id, local_ifindex=n.get("local_ifindex"), remote_key=rkey, first_seen=now)
            s.add(r)
            rows[key] = r
            if not first:
                ev.add("neighbor_added", "low", label, f"new neighbor on {n.get('local_port')}: {n.get('sys_name') or n.get('chassis_id')} "
                       f"({n.get('port_id') or '?'})", ifindex=n.get("local_ifindex"), remote=n.get("sys_name"))
        elif not r.present:
            ev.add("neighbor_added", "low", label, f"neighbor {r.remote_name or rkey} back on {n.get('local_port')}", ifindex=n.get("local_ifindex"),
                   remote=n.get("sys_name"))
        elif r.remote_port and n.get("port_id") and port_key(r.remote_port) != port_key(n["port_id"]):
            ev.add("neighbor_changed", "low", label, f"{n.get('local_port')}: neighbor port changed {r.remote_port} → {n['port_id']}",
                   ifindex=n.get("local_ifindex"), remote=n.get("sys_name"))
        r.local_port = (n.get("local_port") or "")[:128]
        r.protocol = n.get("protocol", "lldp")
        r.remote_name = (n.get("sys_name") or "")[:255]
        r.chassis_id = (n.get("chassis_id") or "")[:128]
        r.remote_port = (n.get("port_id") or "")[:128]
        r.remote_port_desc = (n.get("port_desc") or "")[:255]
        r.remote_mgmt_ip = (n.get("mgmt_ip") or "")[:64]
        r.remote_descr = (n.get("sys_desc") or "")[:300]
        r.capabilities = n.get("caps") or []
        r.present, r.last_seen = True, now
    for key, r in rows.items():
        if key not in seen and r.present:
            r.present = False
            ev.add("neighbor_removed", "medium", f"{r.local_port} → {r.remote_name or r.remote_key}",
                   f"neighbor {r.remote_name or r.remote_key} ({r.remote_port or '?'}) no longer seen on {r.local_port}",
                   ifindex=r.local_ifindex, remote=r.remote_name)
    await s.execute(delete(SwitchNeighbor).where(SwitchNeighbor.switch_id == sw.id, SwitchNeighbor.present.is_(False),
                                                 SwitchNeighbor.last_seen < now - timedelta(days=30)).execution_options(synchronize_session=False))
    metrics.append(_m(now, sw, "switch_neighbors", "", len(seen)))


# ------------------------------------------------------------------ scheduling
async def claim(s: AsyncSession, now: datetime, lease_seconds: int) -> list[int]:
    rows = (await s.execute(select(Switch.id, Switch.last_poll_at, Switch.poll_interval_seconds, Switch.backoff_until).where(
        Switch.monitoring == "active", Switch.credential_id.is_not(None)))).all()
    due = [r.id for r in rows if r.id not in _inflight and not (r.backoff_until and _aware(r.backoff_until) > now) and (r.last_poll_at is None or
           (now - _aware(r.last_poll_at)).total_seconds() >= max(30, r.poll_interval_seconds or 60) - 2)]
    got = []
    for sid in due:
        res = await s.execute(update(Switch).where(Switch.id == sid, (Switch.lease_until.is_(None)) | (Switch.lease_until < now))
                              .values(lease_until=now + timedelta(seconds=lease_seconds)))
        if res.rowcount == 1:
            got.append(sid)
    await s.commit()
    return got


async def run_due(ch, session_factory, now: datetime | None = None, clients: dict | None = None) -> dict:
    """Poll every due switch. Wireless controllers get their own (longer) poll budget and run in the background, so a slow
    controller walk never holds up the polling of every other switch; _inflight prevents a second poll of the same device."""
    fixed_now = now is not None  # callers (tests) that pass `now` get it for every poll
    now = now or datetime.now(timezone.utc)
    st = get_settings()
    async with session_factory() as s:
        ids = await claim(s, now, max(st.switch_poll_timeout_seconds, st.switch_wlc_poll_timeout_seconds) + 60)
        wlc_ids = {i for (i,) in (await s.execute(select(Switch.id).where(Switch.id.in_(ids or [0]), func.lower(Switch.role) == "wlc"))).all()}
    if not ids:
        return {}
    sem = asyncio.Semaphore(max(1, st.switch_max_concurrent_polls))
    results = {}

    async def one(sid: int):
        timeout = st.switch_wlc_poll_timeout_seconds if sid in wlc_ids else st.switch_poll_timeout_seconds
        _inflight.add(sid)
        try:
            async with sem, session_factory() as s:
                sw = await s.get(Switch, sid)
                if sw is None:
                    return
                cred = await s.get(SwitchCredential, sw.credential_id) if sw.credential_id else None
                # sample time = when this poll actually starts, not when the batch was claimed: a switch that waited for a
                # slot would otherwise get skewed rates/timestamps, and the whole batch would stay in lockstep forever
                started = now if fixed_now else datetime.now(timezone.utc)
                try:
                    results[sid] = await asyncio.wait_for(poll_switch(s, ch, sw, cred, client=(clients or {}).get(sid), now=started), timeout)
                except asyncio.TimeoutError:
                    await s.rollback()
                    sw = await s.get(Switch, sid)
                    sw.last_error, sw.last_error_kind = f"poll exceeded {timeout}s", "timeout"
                    results[sid] = {"ok": False, "error": sw.last_error}
                except Exception as e:
                    log.exception("switch poll %s failed", sid)
                    await s.rollback()
                    results[sid] = {"ok": False, "error": type(e).__name__}
                finally:
                    await s.execute(update(Switch).where(Switch.id == sid).values(lease_until=None))
                    await s.commit()
        finally:
            _inflight.discard(sid)
    if clients is None:          # worker: controllers continue in the background
        for i in [x for x in ids if x in wlc_ids]:
            t = asyncio.create_task(one(i))
            _background.add(t)
            t.add_done_callback(_background.discard)
        ids = [x for x in ids if x not in wlc_ids]
    await asyncio.gather(*(one(i) for i in ids))
    return {"polled": len(ids), "background": len(wlc_ids) if clients is None else 0, "failed": sum(1 for r in results.values() if not r.get("ok"))}


async def housekeeping(s: AsyncSession, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    days = get_settings().switch_event_retention_days
    await s.execute(delete(SwitchEvent).where(SwitchEvent.at < now - timedelta(days=days)))
    await s.execute(delete(SwitchPollRun).where(SwitchPollRun.started_at < now - timedelta(days=14)))
    await s.commit()
    from ..wireless.store import housekeeping as wireless_housekeeping
    await wireless_housekeeping(s, now)


async def probe(address: str, cred: SwitchCredential, *, port: int = 161, timeout: float = 3.0, retries: int = 1, client=None,
                groups: list[str] | None = None, wlc: bool = False) -> dict:
    """Test connectivity / credentials / identity / capabilities without storing anything. Returns what would be
    collected (identity, per-metric status and a preview of values)."""
    t0 = time.monotonic()
    try:
        if client is None:
            c = credentials_of(cred)
            check_version_allowed(c.version)
            client = PysnmpClient(address, c, port=port, timeout=timeout, retries=retries)
    except SnmpError as e:
        return {"ok": False, "stage": "configuration", "kind": e.kind, "error": e.message}
    ctx = C.Ctx(client=client, vendor="generic", outcome=Outcome(), snmp_version=cred.version, max_macs=2000, max_vlan_contexts=8)
    try:
        data, report, ran = await run_groups(ctx, groups or [g for g in ORDER if wlc or not g.startswith("wireless_")], group_timeout=45)
    except SnmpError as e:
        return {"ok": False, "stage": "connect", "kind": e.kind, "error": e.message, "duration_ms": int((time.monotonic() - t0) * 1000),
                "hint": {"timeout": "No SNMP answer: check reachability (UDP 161), the switch's SNMP ACL / trusted hosts, and on SNMPv2c the "
                                    "community (agents drop wrong communities silently).",
                         "auth": "The switch rejected the SNMPv3 user, authentication or privacy passphrase / protocol."}.get(e.kind, "")}
    finally:
        await client.close()
    now = datetime.now(timezone.utc)
    ivs = {g: d["interval"] for g, d in GROUPS.items() if wlc or not d.get("wlc")}
    caps = merge_capabilities({}, ctx.outcome, ran, now, ctx.vendor, ivs)
    from .registry import describe
    ifs = data.get("interfaces") or {}
    preview = {"interfaces": len(ifs), "interfaces_up": sum(1 for i in ifs.values() if i["oper"] == "up"),
               "hc_counters": sum(1 for i in ifs.values() if i.get("hc")), "cpu_pct": (data.get("cpu") or {}).get("pct"),
               "memory_pct": (data.get("memory") or {}).get("pct"),
               "temperatures": [(t["name"], t["celsius"]) for t in ((data.get("environment") or {}).get("temperatures") or [])][:8],
               "fans": len((data.get("environment") or {}).get("fans") or []), "psus": len((data.get("environment") or {}).get("psus") or []),
               "stack_members": len((data.get("stack") or {}).get("members") or []), "poe_budget_w": (data.get("poe") or {}).get("budget_w"),
               "poe_used_w": (data.get("poe") or {}).get("used_w"), "vlans": len(data.get("vlans") or {}), "macs": len(data.get("macs") or []),
               "lags": len(((data.get("lacp") or {}).get("lags")) or {}), "stp_mode": (data.get("stp") or {}).get("mode"),
               "route_count": (data.get("routing") or {}).get("route_count")}
    if wlc:
        preview.update(aps=len(data.get("wireless_aps") or {}), radios=len(data.get("wireless_radios") or {}),
                       wlans=len(data.get("wireless_wlans") or {}), clients=len(data.get("wireless_clients") or {}))
    return {"ok": True, "duration_ms": int((time.monotonic() - t0) * 1000), "requests": getattr(client, "requests", 0),
            "identity": {k: v for k, v in (data.get("identity") or {}).items() if k != "serials"},
            "system": {k: data.get(k) for k in ("sys_name", "sys_descr", "sys_object_id", "location", "uptime_s")},
            "groups": report, "capabilities": describe(caps, ctx.vendor, now, ivs), "coverage": coverage(caps, now, ivs),
            "preview": preview, "flags_legend": flag_names(0xFF)}
