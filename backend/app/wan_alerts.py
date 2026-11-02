"""WAN alert rules for the SIEM alert engine (same dedup, cooldown, suppression, notification routing and recovery
pipeline as every other rule). Confirmed outages and recoveries notify directly from the outage records (app/wan.py,
event types wan.outage / wan.recovered); these rules cover sustained conditions around them.

* Paused targets and targets inside a maintenance window are skipped.
* Rules in AUTO_RESOLVE resolve their open alert when the condition clears and send "alert.resolved".
* WAN rule alerts do not open security incidents; ISP incidents come from outage records.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .db.models import IcmpEvent, IcmpTarget, Incident, IspLink, WanCollector, WanMaintenance, WanOutage
from .db.pg import session_factory

STEPS = {
    "wan_latency_sustained": ["Open the target's history: is the RTT rise on one circuit or on every circuit of the site?",
                              "Compare with the SD-WAN health-check latency of the same link", "Check link utilisation for congestion"],
    "wan_loss_sustained": ["Check whether loss is on one target or every target of the circuit (investigation panel)",
                           "Check the WAN interface for errors and the provider's status page", "Raise a ticket with the provider if the circuit shows loss"],
    "wan_jitter_sustained": ["Check utilisation and queueing on the WAN interface", "Compare with SD-WAN SLA jitter for the same link"],
    "wan_flapping": ["Check the WAN interface / last-mile equipment for physical issues", "Ask the provider for line tests",
                     "Consider raising the target's failure threshold only if the flaps are probe artefacts"],
    "wan_long_outage": ["Escalate to the provider with the outage start time and circuit ID", "Confirm the backup circuit is carrying traffic"],
    "wan_site_incidents": ["Look for a common cause at the site (power, firewall, LAN switch)", "Review the site's incident list for patterns"],
    "wan_missing_root_cause": ["Open ISP / WAN → Incidents filtered on 'missing root cause' and record the confirmed cause"],
    "wan_collector_stale": ["Check the worker container is running and its logs", "Target states are frozen until the collector runs again"],
    "wan_low_coverage": ["Check the worker container and the probe errors on the target", "Low coverage makes availability figures less reliable"],
    "wan_availability_low": ["Review the circuit's outages in the selected period", "Compare with the contractual SLA for a credit claim"],
}

DEFAULT_RULES = [
    {"key": "wan_latency_sustained", "name": "WAN: sustained high latency", "severity": "low", "mitre": {},
     "description": "Most checks of a monitored target in the window had an average RTT at or above its RTT threshold.",
     "params": {"window_minutes": 15, "min_fraction": 0.8, "min_checks": 5}},
    {"key": "wan_loss_sustained", "name": "WAN: sustained packet loss", "severity": "medium", "mitre": {},
     "description": "Packet loss over the window reached the target's loss threshold (local probe errors excluded).",
     "params": {"window_minutes": 15, "min_checks": 5}},
    {"key": "wan_jitter_sustained", "name": "WAN: sustained high jitter", "severity": "low", "mitre": {},
     "description": "Average within-check jitter over the window reached the target's jitter threshold (or the rule default).",
     "params": {"window_minutes": 15, "default_jitter_ms": 30, "min_checks": 5}},
    {"key": "wan_flapping", "name": "WAN: circuit flapping", "severity": "medium", "mitre": {},
     "description": "A monitored target went down repeatedly within the window.", "params": {"window_minutes": 60, "min_flaps": 3}},
    {"key": "wan_long_outage", "name": "WAN: long-running outage", "severity": "high", "mitre": {},
     "description": "An outage has lasted longer than the configured minutes and is still in progress.", "params": {"min_minutes": 60}},
    {"key": "wan_site_incidents", "name": "WAN: many incidents at one site", "severity": "medium", "mitre": {},
     "description": "A site accumulated several ISP incidents within the window.", "params": {"window_hours": 24, "min_incidents": 3}},
    {"key": "wan_missing_root_cause", "name": "WAN: incidents without a root cause", "severity": "low", "mitre": {},
     "description": "Resolved ISP incidents older than the grace period still have no root-cause classification.",
     "params": {"grace_hours": 72, "min_incidents": 1}},
    {"key": "wan_collector_stale", "name": "WAN: ICMP collector stopped", "severity": "high", "mitre": {},
     "description": "The ICMP collection loop has not reported a heartbeat: target states are stale.", "params": {"stale_seconds": 180}},
    {"key": "wan_low_coverage", "name": "WAN: insufficient monitoring coverage", "severity": "low", "mitre": {},
     "description": "A target was observed for less than the minimum share of the window (collector gaps, probe errors).",
     "params": {"window_minutes": 60, "min_coverage_pct": 80}},
    {"key": "wan_availability_low", "name": "WAN: circuit availability below target", "severity": "medium", "mitre": {},
     "description": "A circuit's availability over the window fell below its contractual target.", "params": {"window_hours": 24}},
]
AUTO_RESOLVE = {"wan_latency_sustained", "wan_loss_sustained", "wan_jitter_sustained", "wan_long_outage", "wan_missing_root_cause",
                "wan_collector_stale", "wan_low_coverage", "wan_availability_low"}


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _det(key: str, rule: str, explanation: str, *, first, last, count=1, sites=None, evidence=None, dst=None):
    from .alerts.engine import Detection
    ev = {"rule": rule, "investigation": STEPS.get(rule, []), "detected_at": last.isoformat(), **(evidence or {})}
    return Detection(group_key=key, count=count, first_seen=first, last_seen=last, explanation=explanation, sites=sites or [],
                     evidence=ev, event_filter={}, dst_ip=dst)


async def _active_targets(now: datetime):
    from .wan import Ctx, maintenance_matches
    async with session_factory()() as s:
        ctx = await Ctx.load(s)
        ts = (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True)))).scalars().all()
        mt = (await s.execute(select(WanMaintenance).where(WanMaintenance.starts_at <= now, WanMaintenance.ends_at > now))).scalars().all()
    out = [t for t in ts if not any(maintenance_matches(m, site=ctx.site(t), isp=ctx.isp(t), link_id=t.isp_link_id, target_id=t.id) for m in mt)]
    return out, ctx


def _ip(addr: str):
    return addr if addr.replace(".", "").replace(":", "").isalnum() and any(c.isdigit() for c in addr) else None


async def _window_stats(ch, ids: list[int], t0: datetime, t1: datetime) -> dict[int, dict]:
    if not ids:
        return {}
    rows = await ch.aquery(
        "SELECT target_id, countIf(error_class != 'local') AS n, sumIf(sent, error_class != 'local') AS o_sent, "
        "sumIf(received, error_class != 'local') AS o_recv, groupArrayIf(rtt_avg, error_class != 'local' AND up = 1) AS o_rtt_list, "
        "sum(if(length(rtts) > 1, arraySum(arrayMap((a, b) -> abs(a - b), arrayPopFront(rtts), arrayPopBack(rtts))), 0)) AS jit_sum, "
        "sum(if(length(rtts) > 1, length(rtts) - 1, 0)) AS jit_n, min(ts) AS o_first, max(ts) AS o_last "
        "FROM icmp_results WHERE target_id IN {ids:Array(UInt32)} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY target_id",
        {"ids": ids, "t0": t0, "t1": t1})
    return {int(r["target_id"]): r for r in rows}


async def rule_wan_latency_sustained(ch, now, p):
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    ts, ctx = await _active_targets(now)
    st = await _window_stats(ch, [t.id for t in ts], t0, now)
    out = []
    for t in ts:
        r = st.get(t.id)
        vals = [v for v in (r or {}).get("o_rtt_list", []) if v is not None]
        if not r or int(r["n"]) < int(p["min_checks"]) or not vals:
            continue
        slow = sum(1 for v in vals if v >= t.rtt_warn_ms)
        if slow / len(vals) >= float(p["min_fraction"]):
            out.append(_det(f"{t.id}", "wan_latency_sustained",
                            f"{t.name} ({t.address}, {ctx.isp(t)} {ctx.site(t)}): {slow} of {len(vals)} checks at or above {t.rtt_warn_ms:.0f} ms "
                            f"in the last {p['window_minutes']} min (avg {sum(vals) / len(vals):.1f} ms).",
                            first=_aware(r["o_first"]), last=_aware(r["o_last"]), count=slow, sites=[ctx.site(t)], dst=_ip(t.address),
                            evidence={"target_id": t.id, "isp": ctx.isp(t), "threshold_ms": t.rtt_warn_ms, "avg_ms": round(sum(vals) / len(vals), 2)}))
    return out


async def rule_wan_loss_sustained(ch, now, p):
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    ts, ctx = await _active_targets(now)
    st = await _window_stats(ch, [t.id for t in ts], t0, now)
    out = []
    for t in ts:
        r = st.get(t.id)
        if not r or int(r["n"]) < int(p["min_checks"]) or not int(r["o_sent"]):
            continue
        loss = 100 * (int(r["o_sent"]) - int(r["o_recv"])) / int(r["o_sent"])
        if loss >= t.loss_warn_pct and t.state != "down":  # a down target is an outage, already handled
            out.append(_det(f"{t.id}", "wan_loss_sustained",
                            f"{t.name} ({t.address}, {ctx.isp(t)} {ctx.site(t)}): {loss:.1f}% packet loss over {int(r['o_sent'])} probes in the last "
                            f"{p['window_minutes']} min (threshold {t.loss_warn_pct:.0f}%).",
                            first=_aware(r["o_first"]), last=_aware(r["o_last"]), count=int(r["o_sent"]) - int(r["o_recv"]), sites=[ctx.site(t)],
                            dst=_ip(t.address), evidence={"target_id": t.id, "loss_pct": round(loss, 2), "probes": int(r["o_sent"])}))
    return out


async def rule_wan_jitter_sustained(ch, now, p):
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    ts, ctx = await _active_targets(now)
    st = await _window_stats(ch, [t.id for t in ts], t0, now)
    out = []
    for t in ts:
        r = st.get(t.id)
        if not r or int(r["n"]) < int(p["min_checks"]) or not int(r["jit_n"]):
            continue
        jit = float(r["jit_sum"]) / int(r["jit_n"])
        thr = t.jitter_warn_ms or float(p["default_jitter_ms"])
        if jit >= thr:
            out.append(_det(f"{t.id}", "wan_jitter_sustained",
                            f"{t.name} ({t.address}): average jitter {jit:.1f} ms over the last {p['window_minutes']} min (threshold {thr:.0f} ms).",
                            first=_aware(r["o_first"]), last=_aware(r["o_last"]), count=int(r["jit_n"]), sites=[ctx.site(t)], dst=_ip(t.address),
                            evidence={"target_id": t.id, "jitter_ms": round(jit, 2), "threshold_ms": thr}))
    return out


async def rule_wan_flapping(ch, now, p):
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    ts, ctx = await _active_targets(now)
    ids = {t.id: t for t in ts}
    async with session_factory()() as s:
        evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.at >= t0, IcmpEvent.to_state == "down"))).scalars().all()
    by: dict[int, list] = {}
    for e in evs:
        if e.target_id in ids:
            by.setdefault(e.target_id, []).append(_aware(e.at))
    out = []
    for tid, ats in by.items():
        if len(ats) >= int(p["min_flaps"]):
            t = ids[tid]
            out.append(_det(f"{tid}:{min(ats):%Y%m%d%H}", "wan_flapping",
                            f"{t.name} ({t.address}, {ctx.isp(t)} {ctx.site(t)}) went down {len(ats)} times in the last {p['window_minutes']} min.",
                            first=min(ats), last=max(ats), count=len(ats), sites=[ctx.site(t)], dst=_ip(t.address), evidence={"target_id": tid}))
    return out


async def rule_wan_long_outage(ch, now, p):
    lim = now - timedelta(minutes=int(p["min_minutes"]))
    async with session_factory()() as s:
        outs = (await s.execute(select(WanOutage).where(WanOutage.kind == "down", WanOutage.recovered_at.is_(None), WanOutage.started_at <= lim,
                                                        WanOutage.maintenance_id.is_(None)))).scalars().all()
    return [_det(f"outage:{o.id}", "wan_long_outage",
                 f"{o.target_name} ({o.isp_name} {o.site}) has been down for {(now - _aware(o.started_at)).total_seconds() / 60:.0f} min "
                 f"(since {_aware(o.started_at):%Y-%m-%d %H:%M} UTC).", first=_aware(o.started_at), last=now, sites=[o.site],
                 evidence={"outage_id": o.id, "incident_id": o.incident_id, "isp": o.isp_name}) for o in outs]


async def rule_wan_site_incidents(ch, now, p):
    t0 = now - timedelta(hours=int(p["window_hours"]))
    async with session_factory()() as s:
        incs = (await s.execute(select(Incident).where(Incident.category == "wan", Incident.first_seen >= t0))).scalars().all()
    by: dict[str, list] = {}
    for i in incs:
        by.setdefault(i.site or "(no site)", []).append(i)
    return [_det(f"{site}:{t0:%Y%m%d}", "wan_site_incidents", f"{len(xs)} ISP incidents at {site} in the last {p['window_hours']} h.",
                 first=min(_aware(i.first_seen) for i in xs), last=max(_aware(i.last_seen) for i in xs), count=len(xs), sites=[site],
                 evidence={"incident_ids": [i.id for i in xs][:50]})
            for site, xs in by.items() if len(xs) >= int(p["min_incidents"])]


async def rule_wan_missing_root_cause(ch, now, p):
    lim = now - timedelta(hours=int(p["grace_hours"]))
    async with session_factory()() as s:
        incs = (await s.execute(select(Incident).where(Incident.category == "wan", Incident.status.in_(["resolved", "closed"]),
                                                       Incident.root_cause_category.is_(None), Incident.resolved_at <= lim))).scalars().all()
    if len(incs) < int(p["min_incidents"]):
        return []
    return [_det("missing-root-cause", "wan_missing_root_cause",
                 f"{len(incs)} resolved ISP incident(s) older than {p['grace_hours']} h have no root-cause classification.",
                 first=min(_aware(i.first_seen) for i in incs), last=now, count=len(incs), evidence={"incident_ids": [i.id for i in incs][:100]})]


async def rule_wan_collector_stale(ch, now, p):
    async with session_factory()() as s:
        row = await s.get(WanCollector, 1)
        n = len((await s.execute(select(IcmpTarget.id).where(IcmpTarget.enabled.is_(True)))).all())
    if not n or row is None or row.heartbeat_at is None:
        return []
    hb = _aware(row.heartbeat_at)
    if (datetime.now(timezone.utc) - hb).total_seconds() <= int(p["stale_seconds"]):
        return []
    return [_det("collector", "wan_collector_stale", f"No ICMP collector heartbeat since {hb:%Y-%m-%d %H:%M:%S} UTC; {n} target(s) are not being checked.",
                 first=hb, last=now, evidence={"worker": row.worker, "last_error": row.last_error})]


async def rule_wan_low_coverage(ch, now, p):
    from .wan_metrics import target_metrics
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    ts, ctx = await _active_targets(now)
    ts = [t for t in ts if _aware(t.created_at) and _aware(t.created_at) <= t0]  # not new targets still building a baseline
    if not ts:
        return []
    async with session_factory()() as s:
        m = await target_metrics(s, ch, ts, t0, now, ctx)
    out = []
    for t in ts:
        cov = m[t.id]["coverage_pct"]
        if cov is not None and cov < float(p["min_coverage_pct"]):
            out.append(_det(f"{t.id}", "wan_low_coverage",
                            f"{t.name} ({t.address}) was observed for only {cov:.0f}% of the last {p['window_minutes']} min "
                            f"({m[t.id]['local_errors']} local probe error(s)); its availability figures are unreliable.",
                            first=t0, last=now, sites=[ctx.site(t)], evidence={"target_id": t.id, "coverage_pct": cov}))
    return out


async def rule_wan_availability_low(ch, now, p):
    from .wan import settings
    from .wan_metrics import circuits
    t0 = now - timedelta(hours=int(p["window_hours"]))
    async with session_factory()() as s:
        cfg = await settings(s)
        rows = await circuits(s, ch, t0, now, cfg=cfg)
        targets = {lk.id: lk for lk in (await s.execute(select(IspLink))).scalars()}
    out = []
    for r in rows:
        goal = r.get("target_availability") or (targets.get(r["isp_link_id"]).target_availability if r["isp_link_id"] in targets else None)
        if goal is None or r["availability"] is None or r["availability"] >= goal or not r["outages"]:
            continue
        out.append(_det(r["key"], "wan_availability_low",
                        f"{r['name']} ({r['isp']} {r['site']}): {r['availability']:.3f}% availability over {p['window_hours']} h, below its {goal}% target "
                        f"({r['outages']} outage(s), {r['downtime_s'] // 60} min down).", first=t0, last=now, sites=[r["site"]],
                        evidence={"availability": r["availability"], "target": goal, "downtime_s": r["downtime_s"]}))
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}
