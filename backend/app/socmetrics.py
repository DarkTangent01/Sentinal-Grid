"""SOC operations and executive metrics, computed from the stored alerts, incidents and events (no sampled or mock data).

Definitions (shown next to each figure in the UI):
  MTTD  mean time to detect: alert created − first matching event, over alerts created in the period
  MTTA  mean time to acknowledge: incident acknowledged − created
  MTTR  mean time to resolve: incident resolved − created, over incidents resolved in the period
A figure is None when nothing in the period can be measured (never shown as zero).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Alert, Incident
from .incidents import OPEN, priority_of, sla_state, stage_of
from .products import alert_product


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def _stats(seconds: list[float]) -> dict:
    vals = sorted(x for x in seconds if x is not None and x >= 0)
    if not vals:
        return {"mean_s": None, "median_s": None, "p90_s": None, "n": 0}
    return {"mean_s": round(sum(vals) / len(vals), 1), "median_s": round(median(vals), 1), "p90_s": round(vals[min(len(vals) - 1, int(0.9 * len(vals)))], 1), "n": len(vals)}


async def operations(s: AsyncSession, days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    alerts = [a for a in (await s.execute(select(Alert).where(Alert.created_at >= since))).scalars() if alert_product(a.rule_key) == "grid"]
    incs = list((await s.execute(select(Incident).where(Incident.category == "security", (Incident.created_at >= since) | Incident.status.in_(OPEN)))).scalars())
    per_day: dict[str, Counter] = defaultdict(Counter)
    for a in alerts:
        per_day[_aware(a.created_at).date().isoformat()][a.severity] += 1
    judged = [a for a in alerts if a.disposition]
    fp = sum(1 for a in judged if a.disposition in ("false_positive", "benign"))
    by_rule = Counter(a.rule_key for a in alerts)
    names = {a.rule_key: a.name for a in alerts}
    open_incs = [i for i in incs if i.status in OPEN]
    sla = [(i, sla_state(i, now)) for i in incs]
    workload: dict[str, dict] = defaultdict(lambda: {"open": 0, "breached": 0, "p1_p2": 0})
    for i in open_incs:
        w = workload[i.assignee or "(unassigned)"]
        w["open"] += 1
        w["p1_p2"] += priority_of(i) in ("P1", "P2")
        st = sla_state(i, now)
        w["breached"] += st["ack_breached"] or st["resolve_breached"]
    resolved = [i for i in incs if i.resolved_at and _aware(i.resolved_at) >= since]
    inc_day: dict[str, Counter] = defaultdict(Counter)
    for i in incs:
        if _aware(i.created_at) >= since:
            inc_day[_aware(i.created_at).date().isoformat()]["opened"] += 1
    for i in resolved:
        inc_day[_aware(i.resolved_at).date().isoformat()]["resolved"] += 1
    return {
        "days": days,
        "alerts": {"total": len(alerts), "open": sum(1 for a in alerts if a.status in ("new", "investigating")),
                   "by_severity": dict(Counter(a.severity for a in alerts)),
                   "per_day": [{"day": d, **{k: c.get(k, 0) for k in ("critical", "high", "medium", "low", "informational")}} for d, c in sorted(per_day.items())],
                   "top_rules": [{"rule_key": k, "name": names[k], "count": n} for k, n in by_rule.most_common(10)],
                   "judged": len(judged), "false_positive_pct": round(100.0 * fp / len(judged), 1) if judged else None},
        "mttd": _stats([(_aware(a.created_at) - _aware(a.first_seen)).total_seconds() for a in alerts if a.first_seen]),
        "mtta": _stats([(_aware(i.acknowledged_at) - _aware(i.created_at)).total_seconds() for i in incs if i.acknowledged_at and _aware(i.created_at) >= since]),
        "mttr": _stats([(_aware(i.resolved_at) - _aware(i.created_at)).total_seconds() for i in resolved]),
        "incidents": {"open": len(open_incs), "opened": sum(1 for i in incs if _aware(i.created_at) >= since), "resolved": len(resolved),
                      "unassigned": sum(1 for i in open_incs if not i.assignee), "escalated_open": sum(1 for i in open_incs if i.escalated_at),
                      "by_stage": dict(Counter(stage_of(i) for i in open_incs)), "by_priority": dict(Counter(priority_of(i) for i in open_incs)),
                      "closure": dict(Counter(i.closure_reason for i in resolved if i.closure_reason)),
                      "per_day": [{"day": d, "opened": c.get("opened", 0), "resolved": c.get("resolved", 0)} for d, c in sorted(inc_day.items())]},
        "sla": {"ack_breached_open": sum(1 for i, st in sla if i.status in OPEN and st["ack_breached"]),
                "resolve_breached_open": sum(1 for i, st in sla if i.status in OPEN and st["resolve_breached"]),
                "resolved_within_sla_pct": round(100.0 * sum(1 for i in resolved if not sla_state(i, now)["resolve_breached"]) / len(resolved), 1) if resolved else None,
                "breaching": [{"id": i.id, "title": i.title, "severity": i.severity, "priority": priority_of(i), "assignee": i.assignee, "stage": stage_of(i),
                               "ack_breached": st["ack_breached"], "resolve_breached": st["resolve_breached"], "resolve_due": st["resolve_due"]}
                              for i, st in sla if i.status in OPEN and (st["ack_breached"] or st["resolve_breached"])][:50]},
        "workload": sorted(({"analyst": k, **v} for k, v in workload.items()), key=lambda x: -x["open"]),
    }


async def executive(s: AsyncSession, ch, days: int = 7) -> dict:
    from . import risk
    ops = await operations(s, days)
    ev = await ch.aquery("SELECT category, sum(events) AS n FROM events_minute WHERE minute >= now() - toIntervalDay({d:UInt32}) GROUP BY category", {"d": days})
    per_day = await ch.aquery("SELECT toDate(minute) AS day, sum(events) AS n FROM events_minute WHERE minute >= now() - toIntervalDay({d:UInt32}) GROUP BY day ORDER BY day", {"d": days})
    ti = await ch.aquery("SELECT count() AS n, uniqExact(ti_match) AS indicators, uniqExact(src_ip) AS hosts FROM events WHERE event_time >= now() - toIntervalDay({d:UInt32}) "
                         "AND ti_match != ''", {"d": min(days, 7)})
    rk = await risk.ranking(s, days=30, limit=10, min_score=25)
    crit_open = (await s.execute(select(Alert).where(Alert.status.in_(("new", "investigating")), Alert.severity == "critical"))).scalars().all()
    crit_open = [a for a in crit_open if alert_product(a.rule_key) == "grid"]
    # posture: plain, explainable deductions from 100
    deductions = []
    if crit_open:
        deductions.append({"points": min(30, 10 * len(crit_open)), "why": f"{len(crit_open)} open critical alert(s)"})
    b = ops["sla"]["ack_breached_open"] + ops["sla"]["resolve_breached_open"]
    if b:
        deductions.append({"points": min(20, 5 * b), "why": f"{b} SLA breach(es) on open incidents"})
    hi = rk["distribution"].get("critical", 0) + rk["distribution"].get("high", 0)
    if hi:
        deductions.append({"points": min(25, 5 * hi), "why": f"{hi} entity(ies) at high or critical risk"})
    if ops["incidents"]["unassigned"]:
        deductions.append({"points": min(10, 2 * ops["incidents"]["unassigned"]), "why": f"{ops['incidents']['unassigned']} open incident(s) with no owner"})
    if int(ti[0]["n"] or 0):
        deductions.append({"points": min(15, 3 + int(ti[0]["hosts"] or 0)), "why": f"threat-intelligence matches from {int(ti[0]['hosts'] or 0)} host(s) in the last {min(days, 7)} days"})
    return {"days": days, "events_total": sum(int(r["n"]) for r in ev), "events_by_category": {r["category"]: int(r["n"]) for r in ev},
            "events_per_day": [{"day": str(r["day"]), "n": int(r["n"])} for r in per_day],
            "critical_alerts_open": len(crit_open), "open_incidents": ops["incidents"]["open"], "incident_trend": ops["incidents"]["per_day"],
            "alerts_per_day": ops["alerts"]["per_day"], "high_risk_entities": rk["items"], "risk_distribution": rk["distribution"],
            "ti": {"matches": int(ti[0]["n"] or 0), "indicators": int(ti[0]["indicators"] or 0), "hosts": int(ti[0]["hosts"] or 0), "days": min(days, 7)},
            "mttd": ops["mttd"], "mttr": ops["mttr"], "sla": {k: v for k, v in ops["sla"].items() if k != "breaching"},
            "posture": {"score": max(0, 100 - sum(d["points"] for d in deductions)), "deductions": deductions,
                        "method": "100 minus points for open critical alerts, SLA breaches, high-risk entities, unowned incidents and threat-intel matches"}}
