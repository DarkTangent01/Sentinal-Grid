"""WAN metrics from real observations (docs/WAN.md "Metric definitions").

RTT          every successful echo reply's round-trip time (icmp_results.rtts, one value per reply); failed probes have
             no RTT and never enter RTT statistics. "RTT now" is the average of the latest check's replies; average,
             min, max and percentiles cover all replies in the selected window.
Percentiles  nearest rank on the sorted samples: the value at position floor(n * p) (0-based) of the window's replies
             (ClickHouse quantileExact). P99 is shown only with >= 100 samples.
Jitter       mean absolute difference between consecutive RTTs of the replies *within one check* (probes are sent
             200 ms apart), averaged over every such pair in the window. Consecutive checks are never compared, so
             gaps between checks cannot create jitter. This is not RFC 3550 interarrival jitter.
Packet loss  (echo requests sent - replies received) / echo requests sent x 100 over the window's checks; checks
             that failed locally on the SIEM (resolver / socket error, error_class 'local') are excluded and counted
             separately as local errors.
Availability observed time minus downtime, over observed time. Observed time = the window from the later of the window
             start and the target's creation, minus paused time, minus maintenance windows, minus unobserved gaps
             (no check for longer than gap_factor x interval, e.g. collector stopped). Unobserved time is neither
             healthy nor down: it lowers *coverage*, which is reported next to availability. Downtime = confirmed
             outage intervals (started_at → recovered_at, open outages until the window end) inside observed time.
Outages      counted in the window in which they started; downtime and longest outage include the part of an earlier
             outage that overlaps the window. Outages inside a maintenance window are excluded.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import IcmpEvent, IcmpTarget, Incident, IspLink, WanMaintenance, WanOutage
from .isp import Interval, clip, intersect, merge, subtract
from .wan import WAN_OPEN, Ctx, aware, circuit_label, maintenance_matches, settings

EPOCH_GUARD = datetime(2000, 1, 1, tzinfo=timezone.utc)
STATE_RANK = {"down": 0, "degraded": 1, "unknown": 2, "paused": 3, "up": 4}


def _secs(iv: list[Interval]) -> float:
    return sum((b - a).total_seconds() for a, b in iv)


def _f(v, nd=2):
    return None if v is None or v != v else round(float(v), nd)


def _iso(v):
    v = aware(v)
    return v.isoformat() if v else None


async def _maintenance(s: AsyncSession, t0: datetime, t1: datetime) -> list[WanMaintenance]:
    return list((await s.execute(select(WanMaintenance).where(WanMaintenance.starts_at < t1, WanMaintenance.ends_at > t0))).scalars())


def _paused_intervals(t: IcmpTarget, evs: list[IcmpEvent], t0: datetime, t1: datetime) -> list[Interval]:
    out, start = [], None
    for e in evs:
        at = aware(e.at)
        if e.to_state == "paused" and start is None:
            start = at
        elif e.from_state == "paused" and start is not None:
            out.append((start, at))
            start = None
    if start is None and not t.enabled and not evs:  # disabled before pause events existed
        start = aware(t.state_since) or t0
    if start is not None:
        out.append((start, t1))
    return clip(merge(out), t0, t1)


async def target_metrics(s: AsyncSession, ch, targets: list[IcmpTarget], t0: datetime, t1: datetime, ctx: Ctx | None = None,
                         cfg: dict | None = None) -> dict[int, dict]:
    if not targets:
        return {}
    cfg = cfg or await settings(s)
    ctx = ctx or await Ctx.load(s)
    ids = [t.id for t in targets]
    gapf = int(cfg.get("gap_factor", 3))
    thr = {t.id: max(gapf * t.interval_seconds, 90) for t in targets}
    p = {"ids": ids, "t0": t0, "t1": t1}
    agg = {int(r["target_id"]): r for r in await ch.aquery(
        "SELECT target_id, count() AS checks, countIf(error_class = 'local') AS local_errors, "
        "sumIf(sent, error_class != 'local') AS o_sent, sumIf(received, error_class != 'local') AS o_received, "
        "countIf(error_class != 'local' AND up = 0) AS failed_checks, "
        "sum(if(length(rtts) > 1, arraySum(arrayMap((a, b) -> abs(a - b), arrayPopFront(rtts), arrayPopBack(rtts))), "
        "    if(isNull(jitter), 0, assumeNotNull(jitter) * greatest(toInt32(received) - 1, 0)))) AS jit_sum, "
        "sum(if(length(rtts) > 1, length(rtts) - 1, if(isNull(jitter), 0, greatest(toInt32(received) - 1, 0)))) AS jit_n, "
        "avg(sched_delay_ms) AS delay_avg, max(sched_delay_ms) AS delay_max, min(ts) AS o_first, max(ts) AS o_last "
        "FROM icmp_results WHERE target_id IN {ids:Array(UInt32)} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} "
        "GROUP BY target_id", p)}
    rtt = {int(r["target_id"]): r for r in await ch.aquery(
        "SELECT target_id, count() AS n, avg(r) AS o_avg, min(r) AS o_min, max(r) AS o_max, quantilesExact(0.5, 0.95, 0.99)(r) AS q "
        "FROM icmp_results ARRAY JOIN if(empty(rtts), if(isNull(rtt_avg), CAST([], 'Array(Float32)'), [assumeNotNull(rtt_avg)]), rtts) AS r "
        "WHERE target_id IN {ids:Array(UInt32)} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} AND error_class != 'local' "
        "GROUP BY target_id", p)}
    # unobserved gaps: consecutive checks further apart than the target's threshold (from a little before the window)
    pg = {**p, "t0x": t0 - timedelta(seconds=max(thr.values())), "thr_ids": ids, "thr": [int(thr[i] * 1000) for i in ids]}
    gaps: dict[int, list[Interval]] = defaultdict(list)
    first_seen: dict[int, datetime] = {}
    last_seen: dict[int, datetime] = {}
    for r in await ch.aquery(
            "SELECT target_id, min(ts) AS o_first, max(ts) AS o_last FROM icmp_results WHERE target_id IN {ids:Array(UInt32)} "
            "AND ts >= {t0x:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY target_id", pg):
        first_seen[int(r["target_id"])], last_seen[int(r["target_id"])] = aware(r["o_first"]), aware(r["o_last"])
    for r in await ch.aquery(
            "SELECT target_id, prev, ts FROM (SELECT target_id, ts, lagInFrame(ts, 1) OVER (PARTITION BY target_id ORDER BY ts ASC "
            "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS prev FROM icmp_results WHERE target_id IN {ids:Array(UInt32)} "
            "AND ts >= {t0x:DateTime64(3)} AND ts < {t1:DateTime64(3)}) WHERE prev > toDateTime64('2000-01-01 00:00:00', 3) "
            "AND dateDiff('millisecond', prev, ts) > transform(target_id, {thr_ids:Array(UInt32)}, {thr:Array(Int64)}, toInt64(300000)) "
            "ORDER BY target_id, ts LIMIT 20000", pg):
        gaps[int(r["target_id"])].append((aware(r["prev"]), aware(r["ts"])))
    evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.target_id.in_(ids), IcmpEvent.at < t1,
                                                   or_(IcmpEvent.to_state == "paused", IcmpEvent.from_state == "paused"))
                           .order_by(IcmpEvent.at))).scalars().all()
    ev_by: dict[int, list[IcmpEvent]] = defaultdict(list)
    for e in evs:
        ev_by[e.target_id].append(e)
    outs = (await s.execute(select(WanOutage).where(WanOutage.source == "icmp", WanOutage.target_id.in_(ids), WanOutage.started_at < t1,
                                                    or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > t0)))).scalars().all()
    out_by: dict[int, list[WanOutage]] = defaultdict(list)
    for o in outs:
        out_by[o.target_id].append(o)
    maint = await _maintenance(s, t0, t1)
    now = datetime.now(timezone.utc)
    res = {}
    for t in targets:
        fs, ls = first_seen.get(t.id), last_seen.get(t.id)
        created = aware(t.created_at) or t0
        start = max(t0, min(created, fs) if fs else created)
        end = min(t1, now)
        span: list[Interval] = [(start, end)] if end > start else []
        paused = _paused_intervals(t, ev_by.get(t.id, []), start, end) if span else []
        mt = merge([(max(aware(m.starts_at), start), min(aware(m.ends_at), end)) for m in maint
                    if maintenance_matches(m, site=ctx.site(t), isp=ctx.isp(t), link_id=t.isp_link_id, target_id=t.id)
                    and aware(m.ends_at) > start and aware(m.starts_at) < end])
        monitored = subtract(span, merge(paused + mt))
        g = list(gaps.get(t.id, []))
        th = timedelta(seconds=thr[t.id])
        if fs is None:
            g.append((start, end))
        else:
            if fs - start > th:
                g.append((start, fs))
            if end - ls > th:
                g.append((ls, end))
        unobserved = intersect(merge(clip(g, start, end)), monitored)
        observed = subtract(monitored, unobserved)
        tout = out_by.get(t.id, [])
        downs = [o for o in tout if o.kind == "down" and o.maintenance_id is None]
        down_iv = intersect(merge([(aware(o.started_at), aware(o.recovered_at) or end) for o in downs]), observed)
        deg_iv = intersect(merge([(aware(o.started_at), aware(o.recovered_at) or end) for o in tout if o.kind == "degraded"]), observed)
        started_in = [o for o in downs if t0 <= aware(o.started_at) < t1]
        per = [_secs(intersect([(aware(o.started_at), aware(o.recovered_at) or end)], observed)) for o in downs]
        closed = [o.duration_s for o in started_in if o.duration_s is not None]
        obs_s, mon_s, down_s = _secs(observed), _secs(monitored), _secs(down_iv)
        a = agg.get(t.id) or {}
        rr = rtt.get(t.id) or {}
        sent, recv = int(a.get("o_sent") or 0), int(a.get("o_received") or 0)
        n = int(rr.get("n") or 0)
        q = rr.get("q") or [None, None, None]
        jn = int(a.get("jit_n") or 0)
        res[t.id] = {
            "checks": int(a.get("checks") or 0), "failed_checks": int(a.get("failed_checks") or 0), "local_errors": int(a.get("local_errors") or 0),
            "probes_sent": sent, "replies": recv, "loss_pct": round(100 * (sent - recv) / sent, 2) if sent else None,
            "rtt_samples": n, "rtt_ms": _f(rr.get("o_avg")) if n else None, "rtt_min_ms": _f(rr.get("o_min")) if n else None,
            "rtt_max_ms": _f(rr.get("o_max")) if n else None, "rtt_p50_ms": _f(q[0]) if n else None, "rtt_p95_ms": _f(q[1]) if n else None,
            "rtt_p99_ms": _f(q[2]) if n >= 100 else None, "jitter_ms": round(float(a["jit_sum"]) / jn, 2) if jn else None, "jitter_pairs": jn,
            "sched_delay_avg_ms": _f(a.get("delay_avg")), "sched_delay_max_ms": _f(a.get("delay_max")),
            "availability": round(100 * (obs_s - down_s) / obs_s, 4) if obs_s > 0 and a else None,
            "coverage_pct": round(100 * obs_s / mon_s, 2) if mon_s > 0 else None,
            "observed_s": round(obs_s), "unobserved_s": round(_secs(unobserved)), "paused_s": round(_secs(paused)), "maintenance_s": round(_secs(mt)),
            "outages": len(started_in), "downtime_s": round(down_s), "longest_s": round(max(per)) if per else 0,
            "mttr_s": round(sum(closed) / len(closed)) if closed else None, "degraded_s": round(_secs(deg_iv)),
            "ongoing_outage": any(o.recovered_at is None for o in downs),
            "_down": down_iv, "_observed": observed,
        }
    return res


# ------------------------------------------------------------------ live table
def target_row(t: IcmpTarget, m: dict, ctx: Ctx) -> dict:
    lk = ctx.link(t)
    fw = ctx.fws.get(lk.firewall_id) if lk and lk.firewall_id else None
    return {"id": t.id, "name": t.name, "address": t.address, "isp": ctx.isp(t), "site": ctx.site(t), "enabled": t.enabled,
            "circuit": circuit_label(lk, ctx.fws) if lk else None, "circuit_id": lk.circuit_id if lk else "", "isp_link_id": t.isp_link_id,
            "firewall": fw.name if fw else "", "firewall_id": fw.id if fw else None, "role": lk.role if lk else "",
            "state": t.state if t.enabled else "paused", "state_since": _iso(t.state_since), "last_check": _iso(t.last_check),
            "last_ok_at": _iso(t.last_ok_at), "last_rtt_ms": t.last_rtt_ms, "last_loss_pct": t.last_loss_pct, "last_jitter_ms": t.last_jitter_ms,
            "last_error": t.last_error or "", "paused_reason": t.paused_reason or "", "fail_streak": t.fail_streak, "ok_streak": t.ok_streak,
            "interval_seconds": t.interval_seconds, "probes": t.probes, "timeout_ms": t.timeout_ms, "retries": t.retries or 0,
            "down_after": t.down_after, "up_after": t.up_after, "rtt_warn_ms": t.rtt_warn_ms, "loss_warn_pct": t.loss_warn_pct,
            "jitter_warn_ms": t.jitter_warn_ms, "degrade_after": t.degrade_after, "clear_after": t.clear_after,
            "poor_streak": t.poor_streak, "healthy_streak": t.healthy_streak, "isp_name": t.isp_name, "site_override": t.site,
            **{k: v for k, v in m.items() if not k.startswith("_")}}


# ------------------------------------------------------------------ circuits and groups
async def circuits(s: AsyncSession, ch, t0: datetime, t1: datetime, *, targets: list[IcmpTarget] | None = None, ctx: Ctx | None = None,
                   cfg: dict | None = None, metrics: dict | None = None) -> list[dict]:
    """One row per circuit (ISP link with targets or SD-WAN outage records); unlinked targets are their own circuit.
    Circuit downtime = periods when every target of the circuit was down, plus SD-WAN full-link outages."""
    cfg = cfg or await settings(s)
    ctx = ctx or await Ctx.load(s)
    targets = targets if targets is not None else list((await s.execute(select(IcmpTarget))).scalars())
    metrics = metrics if metrics is not None else await target_metrics(s, ch, targets, t0, t1, ctx, cfg)
    now = min(t1, datetime.now(timezone.utc))
    sd = (await s.execute(select(WanOutage).where(WanOutage.source == "sdwan", WanOutage.kind == "down", WanOutage.started_at < t1,
                                                  or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > t0)))).scalars().all()
    sd_by: dict[int, list[WanOutage]] = defaultdict(list)
    for o in sd:
        sd_by[o.isp_link_id].append(o)
    incs = (await s.execute(select(Incident).where(Incident.category == "wan", or_(Incident.status.in_(WAN_OPEN), Incident.first_seen >= t0),
                                                   Incident.first_seen < t1))).scalars().all()
    groups: dict[str, list[IcmpTarget]] = defaultdict(list)
    for t in targets:
        groups[ctx.circuit_key(t)].append(t)
    for lid in sd_by:
        groups.setdefault(f"circuit:{lid}", [])
    rows = []
    for key, ts in groups.items():
        lid = int(key.split(":")[1]) if key.startswith("circuit:") else None
        lk = ctx.links.get(lid) if lid else None
        if key.startswith("circuit:") and lk is None:
            continue
        ms = [metrics[t.id] for t in ts if t.id in metrics]
        live = [t for t in ts if t.enabled]
        states = [t.state or "unknown" for t in live]
        sd_open = any(o.recovered_at is None and o.maintenance_id is None for o in sd_by.get(lid, []))
        if sd_open or (states and all(x == "down" for x in states)):
            state = "down"
        elif any(x in ("down", "degraded") for x in states):
            state = "degraded"
        elif states and all(x == "up" for x in states):
            state = "up"
        elif ts and not live:
            state = "paused"
        else:
            state = "unknown"
        down = None
        for m in ms:
            down = m["_down"] if down is None else intersect(down, m["_down"])
        down = list(down or [])
        observed = merge([x for m in ms for x in m["_observed"]])
        sd_iv = [(max(aware(o.started_at), t0), min(aware(o.recovered_at) or now, now)) for o in sd_by.get(lid, []) if o.maintenance_id is None]
        down = merge(down + [x for x in sd_iv if x[1] > x[0]])
        if not observed and sd_iv:
            observed = [(t0, now)]
        observed = merge(observed + sd_iv)
        down = intersect(down, observed)
        obs_s, down_s = _secs(observed), _secs(down)
        durs = [(b - a).total_seconds() for a, b in down]
        t_first = ts[0] if ts else None
        isp_name = (ctx.isp(t_first) if t_first else "") or ((lk.isp_name or lk.as_org or lk.alias or lk.interface) if lk else "") or "(no provider)"
        site = (ctx.site(t_first) if t_first else "") or ctx.link_site(lk) or "(no site)"
        fw = ctx.fws.get(lk.firewall_id) if lk and lk.firewall_id else None
        my_incs = [i for i in incs if (lid and i.isp_link_id == lid) or (not lid and ts and i.correlation_key == f"target:{ts[0].id}")]
        rows.append({
            "key": key, "isp_link_id": lid, "name": circuit_label(lk, ctx.fws) if lk else (ts[0].name if ts else key),
            "circuit_id": lk.circuit_id if lk else "", "isp": isp_name, "site": site, "firewall": fw.name if fw else "",
            "firewall_id": fw.id if fw else None, "interface": lk.interface if lk else "", "role": lk.role if lk else "",
            "bandwidth_mbps": lk.bandwidth_mbps if lk else None, "state": state, "targets": len(ts), "targets_down": states.count("down"),
            "sdwan_down": sd_open, "outages": sum(1 for a, _ in down if t0 <= a < t1), "downtime_s": round(down_s),
            "avg_outage_s": round(sum(durs) / len(durs)) if durs else None, "longest_s": round(max(durs)) if durs else 0,
            "availability": round(100 * (obs_s - down_s) / obs_s, 4) if obs_s > 0 else None,
            "coverage_pct": _f(sum(m["coverage_pct"] or 0 for m in ms) / len(ms)) if ms and any(m["coverage_pct"] is not None for m in ms) else None,
            "open_incidents": sum(1 for i in my_incs if i.status in WAN_OPEN), "incidents": sum(1 for i in my_incs if aware(i.first_seen) >= t0),
            "target_availability": lk.target_availability if lk else None, "_down": down, "_observed": observed,
        })
    rows.sort(key=lambda r: (STATE_RANK.get(r["state"], 9), r["isp"], r["site"], r["name"]))
    return rows


GROUPS = {"isp_site": lambda r: (r["isp"], r["site"]), "isp": lambda r: (r["isp"], ""), "site": lambda r: ("", r["site"]),
          "circuit": lambda r: (r["key"], ""), "firewall": lambda r: (r["firewall"] or "(no firewall)", "")}


def group_rows(rows: list[dict], by: str) -> list[dict]:
    if by == "circuit":
        return [{**{k: v for k, v in r.items() if not k.startswith("_")}, "group": r["name"], "circuits": 1} for r in rows]
    agg: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        agg[GROUPS[by](r)].append(r)
    out = []
    for (a, b), rs in agg.items():
        down = sum(r["downtime_s"] for r in rs)
        outs = sum(r["outages"] for r in rs)
        durs = [(y - x).total_seconds() for r in rs for x, y in r["_down"]]
        obs = sum(_secs(r["_observed"]) for r in rs)
        worst = min((r["state"] for r in rs), key=lambda x: STATE_RANK.get(x, 9))
        out.append({"group": " · ".join(x for x in (a, b) if x) if by != "isp_site" else f"{a} · {b}", "isp": a if by in ("isp", "isp_site") else "",
                    "site": b if by in ("site", "isp_site") else "", "firewall": a if by == "firewall" else "",
                    "circuits": len(rs), "circuit_names": [r["name"] for r in rs][:20], "state": worst, "outages": outs,
                    "downtime_s": round(down), "avg_outage_s": round(sum(durs) / len(durs)) if durs else None,
                    "longest_s": round(max(durs)) if durs else 0, "availability": round(100 * (obs - down) / obs, 4) if obs > 0 else None,
                    "open_incidents": sum(r["open_incidents"] for r in rs), "incidents": sum(r["incidents"] for r in rs),
                    "targets": sum(r["targets"] for r in rs)})
    return out


# ------------------------------------------------------------------ incident analytics
def _days(t0: datetime, t1: datetime, tz: ZoneInfo) -> list[str]:
    d = t0.astimezone(tz).date()
    end = (t1 - timedelta(microseconds=1)).astimezone(tz).date()
    out = []
    while d <= end:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def tzinfo(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except Exception:
        return ZoneInfo("UTC")


async def incident_analytics(s: AsyncSession, t0: datetime, t1: datetime, *, tz: str = "UTC", site: str | None = None,
                             isp: str | None = None) -> dict:
    """Counting rule: an incident belongs to the window (and the day, in the viewer's time zone) in which it started
    (first_seen = the first outage's started_at). Each incident row is counted once however many outages it holds."""
    z = tzinfo(tz)
    q = select(Incident).where(Incident.category == "wan", Incident.first_seen >= t0, Incident.first_seen < t1)
    if site:
        q = q.where(Incident.site == site)
    if isp:
        q = q.where(Incident.isp_name == isp)
    incs = (await s.execute(q)).scalars().all()
    oq = select(Incident).where(Incident.category == "wan", Incident.status.in_(WAN_OPEN))
    if site:
        oq = oq.where(Incident.site == site)
    if isp:
        oq = oq.where(Incident.isp_name == isp)
    open_now = (await s.execute(oq)).scalars().all()
    res = [(aware(i.resolved_at) - aware(i.first_seen)).total_seconds() for i in incs if i.resolved_at and i.status in ("resolved", "closed")]
    days = _days(t0, t1, z)
    by_day: dict[str, dict[str, int]] = {d: defaultdict(int) for d in days}
    sites_day: dict[str, dict[str, set]] = {d: defaultdict(set) for d in days}
    for i in incs:
        d = aware(i.first_seen).astimezone(z).date().isoformat()
        if d in by_day:
            by_day[d][i.isp_name or "(no provider)"] += 1
            sites_day[d][i.isp_name or "(no provider)"].add(i.site or "(no site)")
    isps = sorted({i.isp_name or "(no provider)" for i in incs}, key=lambda x: -sum(1 for i in incs if (i.isp_name or "(no provider)") == x))
    oq2 = select(WanOutage).where(WanOutage.started_at >= t0, WanOutage.started_at < t1, WanOutage.maintenance_id.is_(None))
    if site:
        oq2 = oq2.where(WanOutage.site == site)
    if isp:
        oq2 = oq2.where(WanOutage.isp_name == isp)
    outs = (await s.execute(oq2)).scalars().all()
    downs = [o for o in outs if o.kind == "down"]
    ttd = [(aware(o.detected_at) - aware(o.started_at)).total_seconds() for o in downs]
    ttr = [o.duration_s for o in downs if o.duration_s is not None]
    by_loc: dict[str, int] = defaultdict(int)
    for i in incs:
        by_loc[i.site or "(no site)"] += 1
    months: dict[str, dict] = {}
    for i in incs:
        m = aware(i.first_seen).astimezone(z).strftime("%Y-%m")
        months.setdefault(m, {"month": m, "incidents": 0, "downtime_s": 0})["incidents"] += 1
    for o in downs:
        m = aware(o.started_at).astimezone(z).strftime("%Y-%m")
        months.setdefault(m, {"month": m, "incidents": 0, "downtime_s": 0})["downtime_s"] += o.duration_s or 0
    now = datetime.now(timezone.utc)
    run = lambda o: o.duration_s if o.duration_s is not None else (min(now, t1) - aware(o.started_at)).total_seconds()  # noqa: E731
    longest = max(downs, key=run, default=None)
    return {
        "window": {"start": t0.isoformat(), "end": t1.isoformat(), "tz": str(z)},
        "totals": {"incidents": len(incs), "open": len(open_now), "avg_resolve_s": round(sum(res) / len(res)) if res else None,
                   "median_resolve_s": round(median(res)) if res else None, "resolved": len(res),
                   "sites_affected": len({i.site for i in incs if i.site}), "missing_root_cause": sum(1 for i in incs if not i.root_cause_category),
                   "outages": len(downs), "degraded_episodes": sum(1 for o in outs if o.kind == "degraded"),
                   "mttd_s": round(sum(ttd) / len(ttd)) if ttd else None, "mttr_s": round(sum(ttr) / len(ttr)) if ttr else None,
                   "longest_outage": {"id": longest.id, "duration_s": round(run(longest)), "target": longest.target_name, "isp": longest.isp_name,
                                      "site": longest.site, "ongoing": longest.recovered_at is None} if longest else None},
        "by_location": sorted([{"site": k, "incidents": v} for k, v in by_loc.items()], key=lambda x: -x["incidents"]),
        "daily": {"days": days, "isps": isps,
                  "series": [{"isp": x, "counts": [by_day[d].get(x, 0) for d in days],
                              "sites": [sorted(sites_day[d].get(x, set())) for d in days]} for x in isps]},
        "by_root_cause": sorted([{"category": k or "(not set)", "incidents": sum(1 for i in incs if (i.root_cause_category or "") == k)}
                                 for k in {i.root_cause_category or "" for i in incs}], key=lambda x: -x["incidents"]),
        "monthly": sorted(months.values(), key=lambda x: x["month"]),
    }


# ------------------------------------------------------------------ per-target history
async def timeseries(ch, target_id: int, t0: datetime, t1: datetime, bucket: int, gap_after: int) -> list[dict]:
    """Buckets with RTT avg / P95 / max, loss, jitter and check counts. Buckets without checks are returned as null
    points (gaps), never as healthy zeros."""
    rows = await ch.aquery(
        f"SELECT toStartOfInterval(ts, INTERVAL {int(bucket)} SECOND) AS t, count() AS checks, countIf(error_class = 'local') AS local_errors, "
        "sumIf(sent, error_class != 'local') AS o_sent, sumIf(received, error_class != 'local') AS o_received, "
        "avgIf(rtt_avg, error_class != 'local') AS o_rtt, max(rtt_max) AS o_rtt_max, "
        "quantileExactArray(0.95)(if(empty(rtts), if(isNull(rtt_avg), CAST([], 'Array(Float32)'), [assumeNotNull(rtt_avg)]), rtts)) AS o_rtt_p95, "
        "avg(jitter) AS o_jitter, min(up) AS all_up "
        "FROM icmp_results WHERE target_id = {id:UInt32} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY t ORDER BY t",
        {"id": target_id, "t0": t0, "t1": t1})
    by = {}
    for r in rows:
        t = aware(r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"])))
        sent = int(r["o_sent"] or 0)
        by[t] = {"t": t.isoformat(), "checks": int(r["checks"]), "local_errors": int(r["local_errors"] or 0),
                 "loss": round(100 * (sent - int(r["o_received"] or 0)) / sent, 2) if sent else None,
                 **{k: _f(r["o_" + k]) for k in ("rtt", "rtt_max", "rtt_p95", "jitter")}}
    out = []
    t = datetime.fromtimestamp((int(t0.timestamp()) // bucket) * bucket, timezone.utc)
    end = min(t1, datetime.now(timezone.utc))
    while t < end:
        out.append(by.get(t) or {"t": t.isoformat(), "checks": 0, "local_errors": 0, "loss": None, "rtt": None, "rtt_max": None,
                                 "rtt_p95": None, "jitter": None, "gap": True})
        t += timedelta(seconds=bucket)
    return out


async def state_timeline(s: AsyncSession, t: IcmpTarget, t0: datetime, t1: datetime) -> list[dict]:
    """Contiguous state segments in [t0, t1] from the transition log (state before t0 from the last earlier event)."""
    before = (await s.execute(select(IcmpEvent).where(IcmpEvent.target_id == t.id, IcmpEvent.at < t0).order_by(IcmpEvent.at.desc()).limit(1))).scalars().first()
    evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.target_id == t.id, IcmpEvent.at >= t0, IcmpEvent.at < t1).order_by(IcmpEvent.at))).scalars().all()
    cur, start = (before.to_state if before else "unknown"), t0
    out = []
    for e in evs:
        at = aware(e.at)
        if at > start:
            out.append({"state": cur, "start": start.isoformat(), "end": at.isoformat(), "duration_s": round((at - start).total_seconds())})
        cur, start = e.to_state, at
    end = min(t1, datetime.now(timezone.utc))
    if end > start:
        out.append({"state": cur, "start": start.isoformat(), "end": end.isoformat(), "duration_s": round((end - start).total_seconds())})
    return out


def outage_out(o: WanOutage) -> dict:
    return {"id": o.id, "source": o.source, "kind": o.kind, "target_id": o.target_id, "isp_link_id": o.isp_link_id, "target": o.target_name,
            "address": o.address, "isp": o.isp_name, "site": o.site, "circuit": o.circuit_name, "last_ok_at": _iso(o.last_ok_at),
            "started_at": _iso(o.started_at), "detected_at": _iso(o.detected_at), "recovered_at": _iso(o.recovered_at),
            "recovery_detected_at": _iso(o.recovery_detected_at), "duration_s": o.duration_s, "ongoing": o.recovered_at is None,
            "time_to_detect_s": round((aware(o.detected_at) - aware(o.started_at)).total_seconds()),
            "failed_checks": o.failed_checks, "evidence": o.evidence or {}, "incident_id": o.incident_id, "maintenance_id": o.maintenance_id}


def circuit_inventory_row(lk: IspLink, ctx: Ctx, targets: list[IcmpTarget]) -> dict:
    fw = ctx.fws.get(lk.firewall_id) if lk.firewall_id else None
    return {"id": lk.id, "label": circuit_label(lk, ctx.fws), "name": lk.name, "circuit_id": lk.circuit_id, "isp_name": lk.isp_name,
            "as_org": lk.as_org, "site": lk.site, "effective_site": ctx.link_site(lk) or "", "location": lk.location,
            "firewall_id": lk.firewall_id, "firewall": fw.name if fw else "", "interface": lk.interface, "alias": lk.alias,
            "gateway": lk.gateway, "bandwidth_mbps": lk.bandwidth_mbps, "role": lk.role, "owner": lk.owner, "notes": lk.notes,
            "support_contact": lk.support_contact, "target_availability": lk.target_availability, "enabled": lk.enabled, "hidden": lk.hidden,
            "monitoring_start": _iso(lk.monitoring_start), "outage_checks": lk.outage_checks or [],
            "targets": [{"id": t.id, "name": t.name, "address": t.address, "state": t.state if t.enabled else "paused",
                         "interval_seconds": t.interval_seconds} for t in targets if t.isp_link_id == lk.id]}
