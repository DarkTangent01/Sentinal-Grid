"""Alert correlation into incidents, plus case-management helpers (SLA, status, disposition)."""
from __future__ import annotations

import json

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .alerts.engine import rule_mitre
from .alerts.rules import TACTICS
from .db.models import Alert, Incident, IncidentComment

SEV = ["informational", "low", "medium", "high", "critical"]
WEIGHT = {"informational": 1, "low": 2, "medium": 5, "high": 10, "critical": 20}
from .platform.sla import SLA, sla_state  # noqa: E402,F401  (moved to the platform package)
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
# Response lifecycle. Each stage maps to the coarse status the rest of the platform reads.
STAGES = ("new", "triage", "investigation", "containment", "eradication", "recovery", "closed")
STAGE_STATUS = {"new": "open", "triage": "in_progress", "investigation": "in_progress", "containment": "in_progress", "eradication": "in_progress",
                "recovery": "resolved", "closed": "closed"}
STATUS_STAGE = {"open": "new", "in_progress": "investigation", "resolved": "recovery", "closed": "closed"}   # when only a status is set
PRIORITY_OF = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "informational": "P4"}


def priority_of(inc: Incident) -> str:
    return inc.priority or PRIORITY_OF.get(inc.severity, "P3")


def stage_of(inc: Incident) -> str:
    """The stored stage, unless the coarse status was changed by older code paths: then the stage that status implies."""
    st = inc.stage or "new"
    return st if STAGE_STATUS.get(st) == inc.status else STATUS_STAGE.get(inc.status, "new")


async def set_stage(s: AsyncSession, inc: Incident, stage: str, user: str, closure_reason: str | None = None) -> None:
    """Move an incident along the lifecycle. Any stage may follow any other (cases reopen, steps get skipped); every
    move is written to the timeline. Closing needs a closure reason (checked by the caller)."""
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}")
    old = stage_of(inc)
    status = STAGE_STATUS[stage]
    if status != inc.status:
        await set_status(s, inc, status, user, closure_reason)
    elif closure_reason:
        inc.closure_reason = closure_reason
    inc.stage = stage
    if old != stage:
        s.add(IncidentComment(incident_id=inc.id, author=user, kind="status", body=f"Stage {old} → {stage}"))


async def escalate(s: AsyncSession, inc: Incident, user: str, to: str, reason: str) -> None:
    inc.escalated_at, inc.escalated_by, inc.escalated_to, inc.escalation_reason = datetime.now(timezone.utc), user, to, reason
    if PRIORITY_OF.get(inc.severity, "P3") != "P1" and (inc.priority or "P9") > "P2":
        inc.priority = "P2"                                   # an escalated case is at least P2
    s.add(IncidentComment(incident_id=inc.id, author=user, kind="status", body=f"Escalated to {to or 'the next tier'}: {reason}"))


CORRELATION_WINDOW = timedelta(hours=24)
OPEN = ("open", "in_progress")


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def entity_of(a: Alert) -> tuple[str, str]:
    if a.rule_key in USER_RULES:
        return "user", a.group_key.split("|")[0]
    if a.rule_key.startswith("tacacs_"):  # network-admin activity joins the user's incident (with VPN / identity alerts)
        u = (a.evidence or {}).get("user")
        return ("user", u) if u else ("tacacs", a.group_key.split(":")[0])
    if a.rule_key.startswith(("switch_", "wireless_")):  # switch / wireless alerts join the incident of the site's firewall, else of the site
        if a.firewall_ids:
            return "firewall", str(a.firewall_ids[0])
        return "site", (a.sites or [a.group_key.split(":")[0]])[0]
    if a.src_ip:
        return "ip", a.src_ip
    return "firewall", str((a.firewall_ids or [0])[0])


def compute(inc: Incident, alerts: list[Alert]) -> None:
    """Recompute incident severity/score/tactics from its alerts.
    Base = highest alert severity; 2 distinct ATT&CK tactics raise it one level; 3+ make it critical."""
    groups = [{"rule_key": a.rule_key, "severity": a.severity, "crit": a.asset_criticality or "", "mitre": a.mitre, "n": 1,
               "first": a.first_seen, "last": a.last_seen, "order": i} for i, a in enumerate(alerts)]
    compute_summary(inc, groups, alerts[0].name if alerts else "")


async def compute_from_db(s: AsyncSession, inc: Incident) -> None:
    """compute() from one grouped query instead of loading every member alert. An incident that gathered 22,470 alerts
    was re-loaded in full (ORM objects with their JSON columns) once per touched alert on every alert pass, which kept
    the worker at 100% CPU and the pass at 15 minutes (docs/performance/INITIAL_AUDIT.md, profile after the split)."""
    from sqlalchemy import String, cast, func
    mt = cast(Alert.mitre, String)
    rows = (await s.execute(select(Alert.rule_key, Alert.severity, Alert.asset_criticality, mt, func.count(), func.min(Alert.first_seen),
                                   func.max(Alert.last_seen), func.min(Alert.id))
                            .where(Alert.incident_id == inc.id).group_by(Alert.rule_key, Alert.severity, Alert.asset_criticality, mt))).all()
    first = (await s.execute(select(Alert.name).where(Alert.incident_id == inc.id).order_by(Alert.id).limit(1))).scalar()
    groups = [{"rule_key": rk, "severity": sev, "crit": crit or "", "mitre": json.loads(m) if m else None, "n": int(n), "first": f, "last": l_,
               "order": mid} for rk, sev, crit, m, n, f, l_, mid in rows]
    compute_summary(inc, groups, first or "")


def compute_summary(inc: Incident, groups: list[dict], first_name: str) -> None:
    """The incident fields from grouped member alerts: rule_key, severity, crit (asset criticality), mitre, n (alerts),
    first / last seen, order (position of the group's first alert). Shared by compute() and compute_from_db()."""
    if not groups:
        return
    # alerts created before ATT&CK mapping existed fall back to the rule catalogue
    mitre = [(g["mitre"] or rule_mitre(g["rule_key"]) or {}) for g in groups]
    tactics = sorted({m.get("tactic") for m in mitre if m.get("tactic")})
    techniques = sorted({t for m in mitre for t in m.get("techniques", [])})
    base = max((g["severity"] for g in groups), key=lambda x: SEV.index(x) if x in SEV else 0, default="low")
    idx = SEV.index(base) if base in SEV else 1
    if len(tactics) >= 3:
        idx = len(SEV) - 1
    elif len(tactics) == 2:
        idx = min(len(SEV) - 1, idx + 1)
    total = sum(g["n"] for g in groups)
    inc.severity = SEV[idx]
    inc.tactics, inc.techniques = tactics, techniques
    inc.rule_keys = sorted({g["rule_key"] for g in groups})
    inc.alert_count = total
    inc.score = sum(WEIGHT.get(g["severity"], 1) * g["n"] for g in groups) + 15 * max(0, len(tactics) - 1)
    inc.first_seen = min(_aware(g["first"]) for g in groups)
    inc.last_seen = max(_aware(g["last"]) for g in groups)
    crit = [g["crit"] for g in sorted(groups, key=lambda g: g["order"]) if g["crit"]]
    inc.asset_criticality = "critical" if "critical" in crit else ("high" if "high" in crit else (crit[0] if crit else ""))
    names = [TACTICS.get(t, t) for t in tactics]
    if len(names) > 1:
        inc.title = f"{inc.entity}: multi-stage activity ({' → '.join(names)})"
    else:
        inc.title = f"{inc.entity}: {first_name}" + (f" (+{total - 1} related)" if total > 1 else "")
    ack, res = SLA.get(inc.severity, SLA["medium"])
    created = _aware(inc.created_at) or datetime.now(timezone.utc)
    inc.sla_ack_due = created + ack
    inc.sla_resolve_due = created + res


async def correlate_alerts(s: AsyncSession, alerts: list[Alert], now: datetime) -> list[tuple[Incident, str]]:
    """Attach alerts to open incidents of the same entity, or open a new incident for high/critical alerts or when
    an entity accumulates alerts from 2+ rules. Returns [(incident, 'created'|'escalated'|'updated')]."""
    await s.flush()
    events: dict[int, tuple[Incident, str]] = {}
    touched: dict[int, Incident] = {}
    before: dict[int, str] = {}
    recent: list[Alert] | None = None
    for a in alerts:
        if a.status in ("resolved", "suppressed"):
            continue
        if a.rule_key.startswith("wan_"):  # WAN conditions: ISP incidents come from outage records (app/wan.py)
            continue
        etype, ent = entity_of(a)
        inc = None
        if a.incident_id:
            inc = await s.get(Incident, a.incident_id)
            if inc and inc.status not in OPEN:
                inc = None
        if inc is None:
            inc = (await s.execute(select(Incident).where(Incident.category == "security", Incident.entity_type == etype, Incident.entity == ent,
                   Incident.status.in_(OPEN), Incident.last_seen >= now - CORRELATION_WINDOW)
                   .order_by(Incident.last_seen.desc()).limit(1))).scalars().first()
        if inc is None:
            if recent is None:  # loaded once per pass (was once per alert): unassigned open alerts of the last 2 h
                recent = (await s.execute(select(Alert).where(Alert.incident_id.is_(None), Alert.status.in_(["new", "investigating"]),
                          Alert.last_seen >= now - timedelta(hours=2)))).scalars().all()
            peers = [p for p in recent if p.incident_id is None and entity_of(p) == (etype, ent)]
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
        if inc.id not in events and inc.id not in before:
            before[inc.id] = inc.severity     # severity at the first touch in this pass, for escalation
        touched[inc.id] = inc
    await s.flush()
    for iid, inc in touched.items():          # each incident recomputed once per pass, from a grouped query
        await compute_from_db(s, inc)
        if iid in events and events[iid][1] == "created" and not inc.tasks:
            inc.tasks = default_tasks(inc.tactics)
        if iid not in events:
            prev = before.get(iid)
            events[iid] = (inc, "escalated" if prev and SEV.index(inc.severity) > SEV.index(prev) else "updated")
            if events[iid][1] == "escalated":
                s.add(IncidentComment(incident_id=iid, author="system", kind="system",
                                      body=f"Severity escalated {prev} → {inc.severity} ({len(inc.tactics)} ATT&CK tactics)."))
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
    if STAGE_STATUS.get(inc.stage or "new") != status:        # callers that only know statuses keep the stage consistent
        inc.stage = STATUS_STAGE[status]
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


