"""Entity risk (hosts and users): an explainable 0-100 score built from the alerts about an entity.

How a score is built (every part is returned, so the page shows exactly why an entity ranks where it does):
  points per alert = severity weight × confidence × recency
      severity     informational 1, low 4, medium 10, high 22, critical 40
      confidence   the rule's confidence (low 0.6, medium 0.8, high 1.0; unknown 0.8)
      recency      1.0 in the last 24 h, 0.6 up to 7 days, 0.3 up to 30 days; resolved alerts count half
  repeats          from the third alert of the same rule on, each counts a quarter (one noisy rule cannot dominate)
  analyst feedback when analysts closed alerts of that rule for that entity as false positive / benign at least twice,
                   that rule counts 20% for the entity; confirmed true positives count 125%
  asset weight     × 1.5 critical, × 1.25 high, × 0.75 low (hosts only; from the asset inventory)
The score is the sum, capped at 100. It ranks where to look first: a high score is not proof of compromise, and
unusual behaviour alone never raises it without a detection behind it.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Alert, Asset
from .incidents import entity_of
from .products import alert_product

SEV_POINTS = {"informational": 1, "low": 4, "medium": 10, "high": 22, "critical": 40}
CONF = {"low": 0.6, "medium": 0.8, "high": 1.0}
CRIT = {"critical": 1.5, "high": 1.25, "normal": 1.0, "": 1.0, "low": 0.75}
LEVELS = ((75, "critical"), (50, "high"), (25, "medium"), (1, "low"))


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def level(score: int) -> str:
    return next((name for floor, name in LEVELS if score >= floor), "none")


def score_entity(alerts: list[Alert], now: datetime, criticality: str = "") -> dict:
    """Score one entity from its alerts (any status). Returns {score, level, factors[], open, feedback}."""
    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_rule[a.rule_key].append(a)
    factors, total = [], 0.0
    for rule, items in by_rule.items():
        fp = sum(1 for a in items if a.disposition in ("false_positive", "benign"))
        tp = sum(1 for a in items if a.disposition == "true_positive")
        fb = 0.2 if fp >= 2 and fp > tp else 1.25 if tp else 1.0
        live = sorted((a for a in items if a.disposition not in ("false_positive", "benign", "duplicate") and a.status != "suppressed"),
                      key=lambda a: _aware(a.last_seen), reverse=True)
        pts = 0.0
        for i, a in enumerate(live):
            age = now - _aware(a.last_seen)
            rec = 1.0 if age <= timedelta(hours=24) else 0.6 if age <= timedelta(days=7) else 0.3
            p = SEV_POINTS.get(a.severity, 4) * CONF.get((a.evidence or {}).get("confidence", ""), 0.8) * rec
            p *= 0.5 if a.status == "resolved" else 1.0
            pts += p * (1.0 if i < 2 else 0.25)
        pts *= fb
        if not live:
            continue
        total += pts
        newest = live[0]
        factors.append({"rule_key": rule, "name": newest.name, "severity": newest.severity, "alerts": len(live), "points": round(pts, 1),
                        "last_seen": _aware(newest.last_seen).isoformat(), "techniques": (newest.mitre or {}).get("techniques") or [],
                        "feedback": "reduced: analysts closed this rule's alerts for this entity as false positive / benign" if fb < 1
                        else "raised: analysts confirmed a true positive" if fb > 1 else "",
                        "newest_alert_id": newest.id, "explanation": (newest.explanation or "")[:300]})
    mult = CRIT.get(criticality or "", 1.0)
    score = min(100, round(total * mult))
    return {"score": score, "level": level(score), "raw_points": round(total, 1), "asset_weight": mult,
            "factors": sorted(factors, key=lambda f: -f["points"]),
            "open": sum(1 for a in alerts if a.status in ("new", "investigating")),
            "tactics": sorted({(a.mitre or {}).get("tactic_name") for a in alerts if (a.mitre or {}).get("tactic_name")} - {None})}


async def entity_alerts(s: AsyncSession, days: int = 30, product: str = "grid") -> dict[tuple[str, str], list[Alert]]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    out: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for a in (await s.execute(select(Alert).where(Alert.last_seen >= since))).scalars():
        if alert_product(a.rule_key) != product:
            continue
        kind, ent = entity_of(a)
        if kind in ("ip", "user") and ent:
            out[(kind, ent)].append(a)
        u = (a.evidence or {}).get("group", {}).get("user") if isinstance((a.evidence or {}).get("group"), dict) else None
        if u and (kind, ent) != ("user", u):
            out[("user", u)].append(a)       # rules grouped by user also count for the user
    return out


async def ranking(s: AsyncSession, days: int = 30, kind: str | None = None, limit: int = 100, min_score: int = 1) -> dict:
    now = datetime.now(timezone.utc)
    groups = await entity_alerts(s, days)
    ips = [e for (k, e) in groups if k == "ip"]
    assets = {a.ip: a for a in (await s.execute(select(Asset).where(Asset.ip.in_(ips)))).scalars()} if ips else {}
    rows = []
    for (k, ent), alerts in groups.items():
        if kind and k != kind:
            continue
        a = assets.get(ent) if k == "ip" else None
        r = score_entity(alerts, now, a.criticality if a else "")
        if r["score"] < min_score:
            continue
        rows.append({"type": k, "entity": ent, "score": r["score"], "level": r["level"], "open_alerts": r["open"], "rules": len(r["factors"]),
                     "top_factor": r["factors"][0]["name"] if r["factors"] else "", "tactics": r["tactics"],
                     "hostname": a.hostname if a else "", "owner": a.owner if a else "", "criticality": a.criticality if a else "",
                     "last_seen": max(f["last_seen"] for f in r["factors"]) if r["factors"] else None})
    rows.sort(key=lambda x: (-x["score"], x["entity"]))
    dist = {name: sum(1 for x in rows if x["level"] == name) for _, name in LEVELS}
    return {"days": days, "entities": len(rows), "distribution": dist, "items": rows[:limit]}


async def detail(s: AsyncSession, kind: str, entity: str, days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    alerts = (await entity_alerts(s, days)).get((kind, entity), [])
    a = (await s.execute(select(Asset).where(Asset.ip == entity))).scalar_one_or_none() if kind == "ip" else None
    r = score_entity(alerts, now, a.criticality if a else "")
    return {"type": kind, "entity": entity, "days": days, **r,
            "asset": None if not a else {"hostname": a.hostname, "owner": a.owner, "criticality": a.criticality, "os": a.os, "last_user": a.last_user, "tags": a.tags},
            "alerts": [{"id": x.id, "name": x.name, "rule_key": x.rule_key, "severity": x.severity, "status": x.status, "disposition": x.disposition,
                        "last_seen": _aware(x.last_seen).isoformat(), "incident_id": x.incident_id} for x in sorted(alerts, key=lambda x: _aware(x.last_seen), reverse=True)[:100]],
            "method": "severity × rule confidence × recency per alert; repeats of one rule count less; analyst verdicts adjust a rule's weight for this "
                      "entity; hosts are weighted by asset criticality; capped at 100"}
