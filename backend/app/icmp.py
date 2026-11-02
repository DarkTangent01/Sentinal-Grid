"""NMS-style ICMP reachability monitoring of public IPs (ISP WAN addresses, gateways, upstream resolvers).

Every enabled target is checked every `interval_seconds` with `probes` echo requests. A check succeeds when at least
one reply arrives. State changes are damped like an NMS: DOWN only after `down_after` consecutive failed checks, back
UP only after `up_after` consecutive good checks; a reachable target with loss or RTT over its thresholds is DEGRADED.
Every change is logged (icmp_events) with how long the previous state lasted; per-check results (RTT, loss, jitter)
go to ClickHouse (icmp_results).

A failed resolution or socket error on the SIEM itself is a *local* error: it is recorded (error_class "local") but
neither counts as a failed check nor as packet loss, because it says nothing about the network. Confirmed DOWN and
DEGRADED episodes become outage records (app/wan.py); see docs/WAN.md for the timing convention.

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

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import IcmpEvent, IcmpTarget

log = logging.getLogger("icmp")
_seq_base = int(time.time()) & 0x7FFF


@dataclass
class ProbeResult:
    sent: int
    received: int
    rtts: list[float]
    error: str = ""
    error_class: str = ""      # "" network result (reply or timeout) | "local" resolver / socket failure on the SIEM
    attempts: int = 1

    @property
    def loss_pct(self) -> float:
        return round(100 * (self.sent - self.received) / self.sent, 1) if self.sent else 100.0

    @property
    def rtt_avg(self) -> float | None:
        return round(sum(self.rtts) / len(self.rtts), 2) if self.rtts else None

    @property
    def jitter(self) -> float | None:
        """Mean absolute difference between consecutive RTTs of this check's replies (in send order)."""
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
        return ProbeResult(count, 0, [], f"cannot resolve: {e}", "local")
    fam, _, _, _, sa = infos[0]
    v6 = fam == socket.AF_INET6
    try:
        sock = socket.socket(fam, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    except OSError as e:
        return ProbeResult(count, 0, [], f"ICMP socket unavailable ({e}); check net.ipv4.ping_group_range", "local")
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
    """Advance the damped state machine for one check observed at `now`. Returns the state-change event, if any.

    unknown → up/degraded after the first good check (baseline); any → down after `down_after` consecutive failed checks;
    down → up/degraded after `up_after` consecutive good checks. Degradation is damped the same way: up → degraded after
    `degrade_after` consecutive *poor* checks (reachable but loss, RTT or jitter over the target's thresholds) and
    degraded → up after `clear_after` consecutive healthy checks, so one slow check never flips the state. A failed check
    interrupts a healthy streak but not a poor one. A local probe error leaves streaks and state untouched."""
    t.last_check = now
    t.last_error = r.error or ""
    if r.error_class == "local":
        return None
    ok = r.received > 0
    if ok:
        t.ok_streak, t.fail_streak = (t.ok_streak or 0) + 1, 0
        if t.ok_streak == 1:
            t.ok_since = now
        t.fail_since = None
        t.last_ok_at = now
    else:
        t.ok_streak, t.fail_streak = 0, (t.fail_streak or 0) + 1
        if t.fail_streak == 1:
            t.fail_since = now
        t.ok_since = None
    jit = r.jitter
    poor = ok and (r.loss_pct >= t.loss_warn_pct or (r.rtt_avg or 0) >= t.rtt_warn_ms
                   or (t.jitter_warn_ms is not None and jit is not None and jit >= t.jitter_warn_ms))
    if poor:
        t.poor_streak, t.healthy_streak = (t.poor_streak or 0) + 1, 0
        if t.poor_streak == 1:
            t.poor_since = now
        t.healthy_since = None
    elif ok:
        t.healthy_streak, t.poor_streak = (t.healthy_streak or 0) + 1, 0
        if t.healthy_streak == 1:
            t.healthy_since = now
        t.poor_since = None
    else:
        t.healthy_streak, t.healthy_since = 0, None
    is_poor = (t.poor_streak or 0) >= (t.degrade_after or 3)
    cur = t.state or "unknown"
    new = cur
    if not ok and t.fail_streak >= t.down_after:
        new = "down"
    elif ok and cur in ("down", "unknown", "paused"):
        if t.ok_streak >= (t.up_after if cur == "down" else 1):
            new = "degraded" if is_poor else "up"
    elif ok and cur == "up" and is_poor:
        new = "degraded"
    elif ok and cur == "degraded" and (t.healthy_streak or 0) >= (t.clear_after or 2):
        new = "up"
    t.last_rtt_ms, t.last_loss_pct, t.last_jitter_ms = r.rtt_avg, r.loss_pct, jit
    if new == cur:
        return None
    since = _aware(t.state_since)
    prev = int((now - since).total_seconds()) if since else None
    detail = (f"{r.received}/{r.sent} replies" + (f", avg {r.rtt_avg} ms" if r.rtt_avg is not None else "") +
              (f"; {t.fail_streak} consecutive failed checks" if new == "down" else "") +
              (f"; {t.ok_streak} consecutive good checks" if cur == "down" else "") +
              (f"; {t.poor_streak} consecutive poor checks" if new == "degraded" and cur != "down" else "") +
              (f"; {t.healthy_streak} consecutive healthy checks" if cur == "degraded" and new == "up" else "") + (f"; {r.error}" if r.error else ""))
    t.state, t.state_since = new, now
    return IcmpEvent(target_id=t.id, at=now, from_state=cur, to_state=new, previous_duration_s=prev, detail=detail)


async def probe(t: IcmpTarget, pinger=ping) -> ProbeResult:
    """One check: `probes` echo requests, retried up to `retries` times when nothing answers. Bounded by a per-target
    deadline so a stuck resolver cannot hold the cycle."""
    budget = t.probes * (t.timeout_ms / 1000 + 0.2) + 2
    attempts = 0
    r = ProbeResult(t.probes, 0, [], "not probed", "local")
    for _ in range(1 + max(0, t.retries or 0)):
        attempts += 1
        try:
            r = await asyncio.wait_for(pinger(t.address, t.probes, t.timeout_ms), budget)
        except asyncio.TimeoutError:
            r = ProbeResult(t.probes, 0, [], f"probe exceeded its {budget:.0f}s deadline", "local")
        if r.received or r.error_class == "local":
            break
    r.attempts = attempts
    return r


def result_row(t: IcmpTarget, r: ProbeResult, now: datetime, delay_ms: float) -> dict:
    return {"ts": now, "target_id": t.id, "address": t.address, "sent": r.sent, "received": r.received,
            "rtt_min": min(r.rtts) if r.rtts else None, "rtt_avg": r.rtt_avg, "rtt_max": max(r.rtts) if r.rtts else None,
            "jitter": r.jitter, "up": 1 if r.received else 0, "state": t.state, "rtts": [float(x) for x in r.rtts],
            "error_class": r.error_class, "error": (r.error or "")[:500], "attempts": min(r.attempts, 255), "sched_delay_ms": float(delay_ms)}


async def check_target(t: IcmpTarget, now: datetime, pinger=ping) -> tuple[dict, IcmpEvent | None]:
    r = await probe(t, pinger)
    ev = evaluate(t, r, now)
    return result_row(t, r, now, 0.0), ev


RESULT_COLUMNS = ["ts", "target_id", "address", "sent", "received", "rtt_min", "rtt_avg", "rtt_max", "jitter", "up", "state",
                  "rtts", "error_class", "error", "attempts", "sched_delay_ms"]


async def apply_transition(s: AsyncSession, t: IcmpTarget, ev: IcmpEvent, r: ProbeResult, ctx, cfg: dict) -> None:
    """Outage bookkeeping for one state change (app/wan.py)."""
    from . import wan
    now = _aware(ev.at)
    checks = {"replies": r.received, "sent": r.sent, "rtt_avg": r.rtt_avg, "loss_pct": r.loss_pct, "error": r.error}
    if ev.from_state == "down":
        await wan.close_outage(s, t, kind="down", recovered_at=_aware(t.ok_since) or now, detected_at=now,
                               evidence={**checks, "good_checks": t.ok_streak, "up_after": t.up_after}, cfg=cfg)
    if ev.from_state == "degraded":
        rec = _aware(t.healthy_since) if ev.to_state == "up" and t.healthy_since else now
        await wan.close_outage(s, t, kind="degraded", recovered_at=rec, detected_at=now,
                               evidence={**checks, "healthy_checks": t.healthy_streak, "clear_after": t.clear_after}, cfg=cfg)
    if ev.to_state == "down":
        await wan.open_outage(s, t, ctx, kind="down", started_at=_aware(t.fail_since) or now, detected_at=now,
                              last_ok_at=_aware(t.last_ok_at), failed_checks=t.fail_streak,
                              evidence={**checks, "failed_checks": t.fail_streak, "down_after": t.down_after}, cfg=cfg)
    elif ev.to_state == "degraded":
        await wan.open_outage(s, t, ctx, kind="degraded", started_at=_aware(t.poor_since) or now, detected_at=now, last_ok_at=_aware(t.last_ok_at),
                              failed_checks=0, evidence={**checks, "poor_checks": t.poor_streak, "degrade_after": t.degrade_after,
                                                         "rtt_warn_ms": t.rtt_warn_ms, "loss_warn_pct": t.loss_warn_pct,
                                                         "jitter_ms": r.jitter, "jitter_warn_ms": t.jitter_warn_ms}, cfg=cfg)


async def claim_due(s: AsyncSession, now: datetime, limit: int) -> list[IcmpTarget]:
    """Due targets, claimed with a short lease so overlapping cycles or a second worker never probe the same target twice."""
    rows = (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True)))).scalars().all()
    due = [t for t in rows if (not t.last_check or (now - _aware(t.last_check)).total_seconds() >= t.interval_seconds - 0.5)
           and (t.lease_until is None or _aware(t.lease_until) <= now)]
    due.sort(key=lambda t: _aware(t.last_check) or datetime.min.replace(tzinfo=timezone.utc))
    claimed = []
    for t in due[:limit]:
        lease = now + timedelta(seconds=t.probes * (t.timeout_ms / 1000 + 0.2) * (1 + (t.retries or 0)) + 30)
        res = await s.execute(update(IcmpTarget).where(IcmpTarget.id == t.id, or_(IcmpTarget.lease_until.is_(None), IcmpTarget.lease_until <= now))
                              .values(lease_until=lease))
        if res.rowcount:
            claimed.append(t)
    await s.commit()
    return claimed


async def run_due(s: AsyncSession, ch, now: datetime | None = None, pinger=ping, concurrency: int = 64, max_per_cycle: int = 2000) -> dict:
    """Check every target whose interval has elapsed. Called every few seconds by the worker.

    Probes run concurrently (bounded); each result is then applied in its own short transaction against a freshly
    locked row, and dropped if the row already holds a newer observation (stale or duplicate job)."""
    from . import wan
    now = now or datetime.now(timezone.utc)
    t_start = time.monotonic()
    claimed = await claim_due(s, now, max_per_cycle)
    enabled = (await s.execute(select(func.count()).select_from(IcmpTarget).where(IcmpTarget.enabled.is_(True)))).scalar_one()
    rows, changes, errors, last_err = [], [], 0, ""
    if claimed:
        sem = asyncio.Semaphore(concurrency)

        async def one(t):
            async with sem:
                return t, await probe(t, pinger)
        results = await asyncio.gather(*(one(t) for t in claimed))
        ctx = await wan.Ctx.load(s)
        cfg = await wan.settings(s)
        for t0_, r in results:
            delay = 0.0
            if t0_.last_check:
                delay = max(0.0, ((now - _aware(t0_.last_check)).total_seconds() - t0_.interval_seconds) * 1000)
            try:
                t = (await s.execute(select(IcmpTarget).where(IcmpTarget.id == t0_.id).with_for_update()
                                     .execution_options(populate_existing=True))).scalars().first()
                if t is None or not t.enabled:
                    await s.rollback()
                    continue
                t.lease_until = None
                if t.last_check and _aware(t.last_check) >= now:  # a newer result is already applied
                    await s.commit()
                    continue
                ev = evaluate(t, r, now)
                if r.error_class == "local":
                    errors += 1
                    last_err = f"{t.address}: {r.error}"
                if ev is not None:
                    s.add(ev)
                    await apply_transition(s, t, ev, r, ctx, cfg)
                    changes.append(f"{t.id}:{ev.from_state}->{ev.to_state}")
                elif t.state == "down":  # down since before outage records existed (upgrade) or a lost write: reconcile once
                    since = _aware(t.state_since) or _aware(t.fail_since) or now
                    await wan.open_outage(s, t, ctx, kind="down", started_at=_aware(t.fail_since) or since, detected_at=since,
                                          last_ok_at=_aware(t.last_ok_at), failed_checks=t.fail_streak,
                                          evidence={"reconciled": True, "note": "target was already down when outage tracking started"}, cfg=cfg)
                await s.commit()
                rows.append(result_row(t, r, now, delay))
            except Exception as e:  # one target's bookkeeping must not stop the others
                await s.rollback()
                errors += 1
                last_err = f"{t0_.address}: {type(e).__name__}: {e}"[:500]
                log.exception("icmp result for target %s failed", t0_.id)
        if rows:
            try:
                await ch.ainsert("icmp_results", rows, RESULT_COLUMNS)
            except Exception as e:
                errors += 1
                last_err = f"storing results: {e}"[:500]
                log.exception("storing icmp results failed")
    backlog = 0
    if len(claimed) >= max_per_cycle:
        backlog = sum(1 for t in (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True)))).scalars()
                      if not t.last_check or (now - _aware(t.last_check)).total_seconds() >= t.interval_seconds)
    c = await wan.collector(s)
    c.worker = socket.gethostname()[:128]
    c.heartbeat_at = datetime.now(timezone.utc)  # wall clock: monitoring-system health, independent of observation times
    if rows or not enabled:
        c.last_success_at = c.heartbeat_at
    if claimed:
        c.last_duration_ms = int((time.monotonic() - t_start) * 1000)
        c.last_checked, c.last_errors, c.last_error, c.backlog = len(rows), errors, last_err, backlog
    await s.commit()
    return {"checked": len(rows), "changes": changes} if changes else {}


async def set_paused(s: AsyncSession, t: IcmpTarget, paused: bool, reason: str, now: datetime | None = None) -> IcmpEvent | None:
    """Pause stops probing and records a 'paused' state; paused time is neither downtime nor counted in availability.
    An outage open at pause time is closed at the pause (its end is unknown, not recovered)."""
    from . import wan
    now = now or datetime.now(timezone.utc)
    if paused == (not t.enabled):
        return None
    cur = t.state or "unknown"
    since = _aware(t.state_since)
    if paused:
        for o in (await s.execute(select(wan.WanOutage).where(wan.WanOutage.target_id == t.id, wan.WanOutage.recovered_at.is_(None)))).scalars():
            await wan.finish_outage(s, o, now, now, {"closed_by": "pause", "note": "monitoring paused; the outage end is unknown"})
        t.enabled, t.state, t.paused_reason = False, "paused", reason[:255]
    else:
        t.enabled, t.state, t.paused_reason = True, "unknown", ""
    t.state_since, t.fail_streak, t.ok_streak, t.fail_since, t.ok_since, t.lease_until = now, 0, 0, None, None, None
    t.poor_streak, t.healthy_streak, t.poor_since, t.healthy_since = 0, 0, None, None
    ev = IcmpEvent(target_id=t.id, at=now, from_state=cur, to_state=t.state, previous_duration_s=int((now - since).total_seconds()) if since else None,
                   detail=("paused: " + reason) if paused else "monitoring resumed")
    s.add(ev)
    return ev


# ------------------------------------------------------------------ analytics
async def overview(s: AsyncSession, ch, t0: datetime, t1: datetime) -> dict:
    """Live table for the ICMP page. Outage counts and downtime come from the outage records (app/wan_metrics.py), the
    same source the ISP incident analytics use."""
    from . import wan, wan_metrics
    targets = (await s.execute(select(IcmpTarget).order_by(IcmpTarget.name))).scalars().all()
    ctx = await wan.Ctx.load(s)
    cfg = await wan.settings(s)
    m = await wan_metrics.target_metrics(s, ch, list(targets), t0, t1, ctx, cfg)
    rows = [wan_metrics.target_row(t, m[t.id], ctx) for t in targets]
    evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.at >= t0, IcmpEvent.at < t1).order_by(IcmpEvent.at.desc()).limit(500))).scalars().all()
    names = {t.id: t for t in targets}
    log_rows = [{"target_id": e.target_id, "name": names[e.target_id].name if e.target_id in names else f"#{e.target_id}",
                 "address": names[e.target_id].address if e.target_id in names else "", "at": _aware(e.at).isoformat(), "from": e.from_state,
                 "to": e.to_state, "previous_duration_s": e.previous_duration_s, "detail": e.detail} for e in evs]
    order = {"down": 0, "degraded": 1, "unknown": 2, "up": 3, "paused": 4}
    rows.sort(key=lambda r: (order.get(r["state"], 5), r["name"]))
    row = await s.get(wan.WanCollector, 1)
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "targets": rows, "events": log_rows,
            "collector": wan.collector_status(row, datetime.now(timezone.utc), int(cfg["stale_after_seconds"])),
            "totals": {"targets": len(rows), "up": sum(1 for r in rows if r["state"] == "up"), "down": sum(1 for r in rows if r["state"] == "down"),
                       "degraded": sum(1 for r in rows if r["state"] == "degraded"), "unknown": sum(1 for r in rows if r["state"] == "unknown"),
                       "paused": sum(1 for r in rows if r["state"] == "paused"), "outages": sum(r["outages"] for r in rows),
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
