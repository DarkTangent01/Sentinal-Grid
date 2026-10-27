"""NMS-style ICMP reachability monitoring of public IPs (ISP WAN addresses, gateways, upstream resolvers).

Every enabled target is checked every `interval_seconds` with `probes` echo requests. A check succeeds when at least
one reply arrives. State changes are damped like an NMS: DOWN only after `down_after` consecutive failed checks, back
UP only after `up_after` consecutive good checks; a reachable target with loss or RTT over its thresholds is DEGRADED.
Every change is logged (icmp_events) with how long the previous state lasted; per-check results (RTT, loss, jitter)
go to ClickHouse (icmp_results).

Probes use unprivileged ICMP datagram sockets (Linux ping_group_range, which Docker opens for containers), so the
SIEM needs no raw-socket capability. Nothing is sent to firewalls except echo requests to the configured addresses.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import IcmpEvent, IcmpTarget, IspLink

log = logging.getLogger("icmp")
_seq_base = int(time.time()) & 0x7FFF


@dataclass
class ProbeResult:
    sent: int
    received: int
    rtts: list[float]
    error: str = ""

    @property
    def loss_pct(self) -> float:
        return round(100 * (self.sent - self.received) / self.sent, 1) if self.sent else 100.0

    @property
    def rtt_avg(self) -> float | None:
        return round(sum(self.rtts) / len(self.rtts), 2) if self.rtts else None

    @property
    def jitter(self) -> float | None:
        if len(self.rtts) < 2:
            return None
        return round(sum(abs(a - b) for a, b in zip(self.rtts, self.rtts[1:])) / (len(self.rtts) - 1), 2)


def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    total = sum(struct.unpack(f"!{len(b) // 2}H", b))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


async def ping(address: str, count: int = 3, timeout_ms: int = 1000, gap: float = 0.2) -> ProbeResult:
    """Send `count` ICMP echo requests and wait up to timeout_ms for each reply (IPv4 and IPv6)."""
    global _seq_base
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(address, None, type=socket.SOCK_DGRAM)
    except OSError as e:
        return ProbeResult(count, 0, [], f"cannot resolve: {e}")
    fam, _, _, _, sa = infos[0]
    v6 = fam == socket.AF_INET6
    try:
        sock = socket.socket(fam, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    except OSError as e:
        return ProbeResult(count, 0, [], f"ICMP socket unavailable ({e}); check net.ipv4.ping_group_range")
    sock.setblocking(False)
    sent: dict[int, float] = {}
    rtts: dict[int, float] = {}
    try:
        for i in range(count):
            _seq_base = (_seq_base + 1) & 0xFFFF
            seq = _seq_base
            payload = b"sentinel-grid-probe"
            hdr = struct.pack("!BBHHH", 128 if v6 else 8, 0, 0, 0, seq)
            # Linux fills the ICMP checksum for ping sockets; BSD/macOS do not (ICMPv6's is always kernel-computed)
            pkt = hdr if v6 else struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), 0, seq)
            pkt += payload
            sent[seq] = time.monotonic()
            try:
                await loop.sock_sendto(sock, pkt, sa)
            except OSError as e:
                return ProbeResult(count, len(rtts), list(rtts.values()), f"send failed: {e}")
            deadline = sent[seq] + timeout_ms / 1000
            while seq not in rtts:  # replies to earlier sequence numbers may arrive late; keep any that match
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 2048), left)
                except asyncio.TimeoutError:
                    break
                if not v6 and len(data) >= 28 and data[0] >> 4 == 4:  # BSD/macOS include the IPv4 header; Linux does not
                    data = data[(data[0] & 0x0F) * 4:]
                if len(data) >= 8 and data[0] == (129 if v6 else 0):
                    rseq = struct.unpack("!H", data[6:8])[0]
                    if rseq in sent and rseq not in rtts:
                        rtts[rseq] = round((time.monotonic() - sent[rseq]) * 1000, 2)
            if i < count - 1:
                await asyncio.sleep(gap)
    finally:
        sock.close()
    return ProbeResult(count, len(rtts), [rtts[k] for k in sorted(rtts)])


def _aware(v):
    """Timezone-aware UTC datetime from a datetime or an ISO / ClickHouse string."""
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def evaluate(t: IcmpTarget, r: ProbeResult, now: datetime) -> IcmpEvent | None:
    """Advance the damped state machine for one check. Returns the state-change event, if any."""
    ok = r.received > 0
    t.ok_streak, t.fail_streak = (t.ok_streak + 1, 0) if ok else (0, t.fail_streak + 1)
    poor = ok and (r.loss_pct >= t.loss_warn_pct or (r.rtt_avg or 0) >= t.rtt_warn_ms)
    cur = t.state or "unknown"
    new = cur
    if not ok and t.fail_streak >= t.down_after:
        new = "down"
    elif ok and cur in ("down", "unknown"):
        if t.ok_streak >= (t.up_after if cur == "down" else 1):
            new = "degraded" if poor else "up"
    elif ok and cur in ("up", "degraded"):
        new = "degraded" if poor else "up"
    t.last_check, t.last_rtt_ms, t.last_loss_pct = now, r.rtt_avg, r.loss_pct
    if new == cur:
        return None
    since = _aware(t.state_since)
    prev = int((now - since).total_seconds()) if since else None
    detail = (f"{r.received}/{r.sent} replies" + (f", avg {r.rtt_avg} ms" if r.rtt_avg is not None else "") +
              (f"; {t.fail_streak} consecutive failed checks" if new == "down" else "") + (f"; {r.error}" if r.error else ""))
    t.state, t.state_since = new, now
    return IcmpEvent(target_id=t.id, at=now, from_state=cur, to_state=new, previous_duration_s=prev, detail=detail)


async def check_target(t: IcmpTarget, now: datetime, pinger=ping) -> tuple[dict, IcmpEvent | None]:
    r = await pinger(t.address, t.probes, t.timeout_ms)
    ev = evaluate(t, r, now)
    row = {"ts": now, "target_id": t.id, "address": t.address, "sent": r.sent, "received": r.received,
           "rtt_min": min(r.rtts) if r.rtts else None, "rtt_avg": r.rtt_avg, "rtt_max": max(r.rtts) if r.rtts else None,
           "jitter": r.jitter, "up": 1 if r.received else 0, "state": t.state}
    return row, ev


RESULT_COLUMNS = ["ts", "target_id", "address", "sent", "received", "rtt_min", "rtt_avg", "rtt_max", "jitter", "up", "state"]


async def run_due(s: AsyncSession, ch, now: datetime | None = None, pinger=ping, concurrency: int = 64) -> dict:
    """Check every target whose interval has elapsed. Called every few seconds by the worker."""
    now = now or datetime.now(timezone.utc)
    targets = (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True)))).scalars().all()
    due = [t for t in targets if not t.last_check or (now - _aware(t.last_check)).total_seconds() >= t.interval_seconds - 0.5]
    if not due:
        return {}
    sem = asyncio.Semaphore(concurrency)

    async def one(t):
        async with sem:
            return await check_target(t, now, pinger)
    results = await asyncio.gather(*(one(t) for t in due))
    rows, changes = [], []
    for row, ev in results:
        rows.append(row)
        if ev is not None:
            s.add(ev)
            changes.append(f"{ev.from_state}->{ev.to_state}")
    await ch.ainsert("icmp_results", rows, RESULT_COLUMNS)
    await s.commit()
    return {"checked": len(rows), "changes": changes} if changes else {}


# ------------------------------------------------------------------ analytics
def _down_intervals(events: list[IcmpEvent], state_before: str, t0: datetime, t1: datetime) -> list[tuple[datetime, datetime]]:
    out, start = [], (t0 if state_before == "down" else None)
    for e in events:
        at = _aware(e.at)
        if e.to_state == "down" and start is None:
            start = at
        elif e.from_state == "down" and e.to_state != "down" and start is not None:
            out.append((start, at))
            start = None
    if start is not None:
        out.append((start, t1))
    return out


def isp_label(t: IcmpTarget, links: dict[int, IspLink]) -> str:
    lk = links.get(t.isp_link_id) if t.isp_link_id else None
    if lk:
        return lk.isp_name or lk.as_org or lk.alias or lk.interface
    return t.isp_name or "(no provider)"


async def overview(s: AsyncSession, ch, t0: datetime, t1: datetime) -> dict:
    targets = (await s.execute(select(IcmpTarget).order_by(IcmpTarget.name))).scalars().all()
    links = {x.id: x for x in (await s.execute(select(IspLink))).scalars()}
    evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.at >= t0 - timedelta(days=31), IcmpEvent.at < t1)
                           .order_by(IcmpEvent.at))).scalars().all()
    stats = {int(r["target_id"]): r for r in await ch.aquery(
        "SELECT target_id, count() AS checks, sum(up) AS ok_checks, sum(sent) AS sent, sum(received) AS received, "
        "avg(rtt_avg) AS rtt, quantile(0.95)(rtt_avg) AS rtt95, max(rtt_max) AS rtt_peak, avg(jitter) AS jitter, min(ts) AS first "
        "FROM icmp_results WHERE ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY target_id", {"t0": t0, "t1": t1})}
    rows, log_rows = [], []
    for t in targets:
        tev = [e for e in evs if e.target_id == t.id]
        before = [e for e in tev if _aware(e.at) < t0]
        inside = [e for e in tev if _aware(e.at) >= t0]
        state_before = before[-1].to_state if before else "unknown"
        st = stats.get(t.id) or {}
        first = _aware(st.get("first")) if st.get("first") else None
        span_start = max(t0, first) if first and state_before == "unknown" else t0
        downs = [(max(a, span_start), b) for a, b in _down_intervals(inside, state_before, t0, t1) if b > span_start]
        down_s = sum((b - a).total_seconds() for a, b in downs)
        span = (t1 - span_start).total_seconds()
        durs = [(b - a).total_seconds() for a, b in downs]
        sent, recv = int(st.get("sent") or 0), int(st.get("received") or 0)

        def f(v):
            return None if v is None or v != v else round(float(v), 2)
        rows.append({"id": t.id, "name": t.name, "address": t.address, "isp": isp_label(t, links), "site": t.site, "enabled": t.enabled,
                     "state": t.state if t.enabled else "disabled", "state_since": t.state_since.isoformat() if t.state_since else None,
                     "last_check": t.last_check.isoformat() if t.last_check else None, "last_rtt_ms": t.last_rtt_ms,
                     "last_loss_pct": t.last_loss_pct, "interval_seconds": t.interval_seconds, "probes": t.probes, "timeout_ms": t.timeout_ms,
                     "down_after": t.down_after, "up_after": t.up_after, "rtt_warn_ms": t.rtt_warn_ms, "loss_warn_pct": t.loss_warn_pct,
                     "isp_link_id": t.isp_link_id, "isp_name": t.isp_name,
                     "availability": round(100 * (span - down_s) / span, 4) if span > 0 and st else None,
                     "outages": sum(1 for e in inside if e.to_state == "down"), "downtime_s": round(down_s),
                     "longest_s": round(max(durs)) if durs else 0, "mttr_s": round(sum(durs) / len(durs)) if durs else 0,
                     "checks": int(st.get("checks") or 0), "loss_pct": round(100 * (sent - recv) / sent, 2) if sent else None,
                     "rtt_ms": f(st.get("rtt")), "rtt_p95_ms": f(st.get("rtt95")), "rtt_peak_ms": f(st.get("rtt_peak")),
                     "jitter_ms": f(st.get("jitter")), "_downs": downs})
        log_rows += [{"target_id": t.id, "name": t.name, "address": t.address, "at": _aware(e.at).isoformat(), "from": e.from_state,
                      "to": e.to_state, "previous_duration_s": e.previous_duration_s, "detail": e.detail} for e in inside]
    order = {"down": 0, "degraded": 1, "unknown": 2, "up": 3, "disabled": 4}
    rows.sort(key=lambda r: (order.get(r["state"], 5), r["name"]))
    for r in rows:
        r.pop("_downs")
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "targets": rows,
            "events": sorted(log_rows, key=lambda x: x["at"], reverse=True)[:500],
            "totals": {"targets": len(rows), "down": sum(1 for r in rows if r["state"] == "down"),
                       "degraded": sum(1 for r in rows if r["state"] == "degraded"), "outages": sum(r["outages"] for r in rows),
                       "downtime_s": sum(r["downtime_s"] for r in rows)}}


async def timeseries(ch, target_id: int, t0: datetime, t1: datetime, bucket: int) -> list[dict]:
    rows = await ch.aquery(
        f"SELECT toStartOfInterval(ts, INTERVAL {int(bucket)} SECOND) AS t, avg(rtt_avg) AS rtt, max(rtt_max) AS rtt_max, "
        "avg(jitter) AS jitter, 100 * (1 - sum(received) / sum(sent)) AS loss, min(up) AS all_up FROM icmp_results "
        "WHERE target_id = {id:UInt32} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY t ORDER BY t",
        {"id": target_id, "t0": t0, "t1": t1})
    out = []
    for r in rows:
        t = r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))
        out.append({"t": _aware(t).isoformat(), **{k: (None if r[k] is None or r[k] != r[k] else round(float(r[k]), 2))
                                                   for k in ("rtt", "rtt_max", "jitter", "loss")}})
    return out


def validate_address(addr: str) -> str:
    """Public or private IP / hostname; loopback, link-local, multicast and unspecified addresses are refused."""
    addr = addr.strip()
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        if not addr or len(addr) > 253 or not all(c.isalnum() or c in "-." for c in addr):
            raise ValueError("enter an IP address or hostname")
        return addr.lower()
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError("loopback, link-local, multicast and unspecified addresses cannot be monitored")
    return str(ip)
