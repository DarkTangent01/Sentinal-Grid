"""Alert correlation into incidents, plus case-management helpers (SLA, status, disposition)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .alerts.rules import RULE_MITRE, TACTICS
from .db.models import Alert, Incident, IncidentComment

SEV = ["informational", "low", "medium", "high", "critical"]
WEIGHT = {"informational": 1, "low": 2, "medium": 5, "high": 10, "critical": 20}
SLA = {  # (acknowledge, resolve)
    "critical": (timedelta(minutes=15), timedelta(hours=4)),
    "high": (timedelta(hours=1), timedelta(hours=24)),
    "medium": (timedelta(hours=4), timedelta(days=3)),
    "low": (timedelta(hours=24), timedelta(days=7)),
    "informational": (timedelta(days=3), timedelta(days=14)),
}
USER_RULES = {"impossible_travel", "win_lockout", "win_bruteforce"}
BASE_TASKS = ["Triage: confirm the activity in the related events and decide true / false positive",
              "Identify the asset owner and business impact", "Contain if malicious (block, isolate, disable account)",
              "Record root cause and close with a disposition"]
TACTIC_TASKS = {  # extra checklist items by MITRE ATT&CK tactic
    "TA0011": ["Check which other hosts contacted the same destination / domain", "Block the C2 destination at the perimeter (generate CLI)"],
    "TA0010": ["Quantify data sent and identify the destination owner", "Check for staging (large internal transfers) before the upload"],
    "TA0006": ["Reset or lock the targeted credentials", "Review successful logins from the same source"],
    "TA0008": ["List every internal host the source reached on admin ports", "Check those hosts for new services / accounts"],
    "TA0007": ["Confirm whether the scan source is an approved scanner", "Check for follow-up connections to discovered services"],
    "TA0043": ["Confirm whether the scan source is an approved scanner"],
    "TA0001": ["Check the exposed service and its patch level", "Verify MFA / allow-listing on remote access"],
    "TA0005": ["Review who changed the configuration and whether it was approved"],
}


def default_tasks(tactics: list[str]) -> list[dict]:
    from secrets import token_hex
    items = BASE_TASKS[:2] + [t for tac in tactics for t in TACTIC_TASKS.get(tac, [])] + BASE_TASKS[2:]
    seen, out = set(), []
    for t in items:
        if t not in seen:
            seen.add(t)
            out.append({"id": token_hex(4), "text": t, "done": False, "added_by": "system"})
    return out
CORRELATION_WINDOW = timedelta(hours=24)
OPEN = ("open", "in_progress")


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def entity_of(a: Alert) -> tuple[str, str]:
    if a.rule_key in USER_RULES:
        return "user", a.group_key.split("|")[0]
    if a.src_ip:
        return "ip", a.src_ip
    return "firewall", str((a.firewall_ids or [0])[0])


def compute(inc: Incident, alerts: list[Alert]) -> None:
    """Recompute incident severity/score/tactics from its alerts.
    Base = highest alert severity; 2 distinct ATT&CK tactics raise it one level; 3+ make it critical."""
    # alerts created before ATT&CK mapping existed fall back to the rule catalogue
    mitre = [(a.mitre or RULE_MITRE.get(a.rule_key) or {}) for a in alerts]
    tactics = sorted({m.get("tactic") for m in mitre if m.get("tactic")})
    techniques = sorted({t for m in mitre for t in m.get("techniques", [])})
    base = max((a.severity for a in alerts), key=lambda x: SEV.index(x) if x in SEV else 0, default="low")
    idx = SEV.index(base) if base in SEV else 1
    if len(tactics) >= 3:
        idx = len(SEV) - 1
    elif len(tactics) == 2:
        idx = min(len(SEV) - 1, idx + 1)
    inc.severity = SEV[idx]
    inc.tactics, inc.techniques = tactics, techniques
    inc.rule_keys = sorted({a.rule_key for a in alerts})
    inc.alert_count = len(alerts)
    inc.score = sum(WEIGHT.get(a.severity, 1) for a in alerts) + 15 * max(0, len(tactics) - 1)
    inc.first_seen = min(_aware(a.first_seen) for a in alerts)
    inc.last_seen = max(_aware(a.last_seen) for a in alerts)
    crit = [a.asset_criticality for a in alerts if a.asset_criticality]
    inc.asset_criticality = "critical" if "critical" in crit else ("high" if "high" in crit else (crit[0] if crit else ""))
    names = [TACTICS.get(t, t) for t in tactics]
    if len(names) > 1:
        inc.title = f"{inc.entity}: multi-stage activity ({' → '.join(names)})"
    else:
        inc.title = f"{inc.entity}: {alerts[0].name}" + (f" (+{len(alerts) - 1} related)" if len(alerts) > 1 else "")
    ack, res = SLA.get(inc.severity, SLA["medium"])
    created = _aware(inc.created_at) or datetime.now(timezone.utc)
    inc.sla_ack_due = created + ack
    inc.sla_resolve_due = created + res


async def correlate_alerts(s: AsyncSession, alerts: list[Alert], now: datetime) -> list[tuple[Incident, str]]:
    """Attach alerts to open incidents of the same entity, or open a new incident for high/critical alerts or when
    an entity accumulates alerts from 2+ rules. Returns [(incident, 'created'|'escalated'|'updated')]."""
    await s.flush()
    events: dict[int, tuple[Incident, str]] = {}
    for a in alerts:
        if a.status in ("resolved", "suppressed"):
            continue
        etype, ent = entity_of(a)
        inc = None
        if a.incident_id:
            inc = await s.get(Incident, a.incident_id)
            if inc and inc.status not in OPEN:
                inc = None
        if inc is None:
            inc = (await s.execute(select(Incident).where(Incident.entity_type == etype, Incident.entity == ent,
                   Incident.status.in_(OPEN), Incident.last_seen >= now - CORRELATION_WINDOW)
                   .order_by(Incident.last_seen.desc()).limit(1))).scalars().first()
        if inc is None:
            peers = (await s.execute(select(Alert).where(Alert.incident_id.is_(None), Alert.status.in_(["new", "investigating"]),
                     Alert.last_seen >= now - timedelta(hours=2)))).scalars().all()
            peers = [p for p in peers if entity_of(p) == (etype, ent)]
            if a.severity not in ("high", "critical") and len({p.rule_key for p in peers} | {a.rule_key}) < 2:
                continue  # a single low/medium alert stays standalone
            inc = Incident(title=a.name, entity_type=etype, entity=ent, status="open", created_at=now, evidence=[], tasks=[], linked=[])
            s.add(inc)
            await s.flush()
            s.add(IncidentComment(incident_id=inc.id, author="system", kind="system",
                                  body=f"Incident opened by correlation from alert #{a.id} ({a.name})."))
            for p in peers:
                p.incident_id = inc.id
            events[inc.id] = (inc, "created")
        a.incident_id = inc.id
        await s.flush()
        members = (await s.execute(select(Alert).where(Alert.incident_id == inc.id))).scalars().all()
        before = inc.severity if inc.id not in events else None
        compute(inc, members)
        if inc.id in events and events[inc.id][1] == "created" and not inc.tasks:
            inc.tasks = default_tasks(inc.tactics)
        if inc.id not in events:
            events[inc.id] = (inc, "escalated" if before and SEV.index(inc.severity) > SEV.index(before) else "updated")
            if events[inc.id][1] == "escalated":
                s.add(IncidentComment(incident_id=inc.id, author="system", kind="system",
                                      body=f"Severity escalated {before} → {inc.severity} ({len(inc.tactics)} ATT&CK tactics)."))
    await s.flush()
    from .notify import incident_event
    for inc, kind in events.values():
        if kind in ("created", "escalated"):
            await incident_event(s, inc, kind)
    return list(events.values())


async def set_status(s: AsyncSession, inc: Incident, status: str, user: str, closure_reason: str | None = None) -> None:
    now = datetime.now(timezone.utc)
    old = inc.status
    inc.status = status
    if status == "in_progress" and not inc.acknowledged_at:
        inc.acknowledged_at = now
    if status in ("resolved", "closed"):
        inc.resolved_at = inc.resolved_at or now
        inc.acknowledged_at = inc.acknowledged_at or now
        inc.closure_reason = closure_reason or inc.closure_reason
        # propagate the analyst's verdict to member alerts (feeds per-rule false-positive rates)
        for a in (await s.execute(select(Alert).where(Alert.incident_id == inc.id))).scalars():
            a.disposition = inc.closure_reason
            if a.status in ("new", "investigating"):
                a.status = "resolved"
    elif status in OPEN:
        inc.resolved_at = None
    s.add(IncidentComment(incident_id=inc.id, author=user, kind="status",
                          body=f"Status {old} → {status}" + (f" ({closure_reason})" if closure_reason else "")))


def sla_state(inc: Incident, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ack_due, res_due = _aware(inc.sla_ack_due), _aware(inc.sla_resolve_due)
    acked, resolved = _aware(inc.acknowledged_at), _aware(inc.resolved_at)
    return {
        "ack_due": ack_due.isoformat() if ack_due else None, "resolve_due": res_due.isoformat() if res_due else None,
        "ack_breached": bool(ack_due and ((acked or now) > ack_due)),
        "resolve_breached": bool(res_due and ((resolved or now) > res_due)),
    }
