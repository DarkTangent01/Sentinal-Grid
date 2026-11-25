"""APIs: incidents/cases, rule effectiveness, notifications, saved searches, reports."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.ql import QLError, compile_ql
from ..db.ch import ClickHouse
from ..db.models import (
    Alert,
    Incident,
    IncidentComment,
    SavedSearch,
    User,
)
from ..db.pg import get_session
from ..incidents import (
    OPEN,
    SEV,
    escalate,
    priority_of,
    set_stage,
    set_status,
    sla_state,
    stage_of,
)
from ..searches import count_matches
from .alerts import alert_out
from .deps import audit, ch_dep, current_user, iso

router = APIRouter(prefix="/api", tags=["soc"])


# ------------------------------------------------------------------ incidents / cases
def inc_out(i: Incident) -> dict:
    return {"id": i.id, "title": i.title, "entity_type": i.entity_type, "entity": i.entity, "status": i.status, "severity": i.severity,
            "score": i.score, "tactics": i.tactics, "techniques": i.techniques, "rule_keys": i.rule_keys, "alert_count": i.alert_count,
            "asset_criticality": i.asset_criticality, "assignee": i.assignee, "summary": i.summary, "closure_reason": i.closure_reason,
            "evidence": i.evidence, "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "created_at": iso(i.created_at),
            "acknowledged_at": iso(i.acknowledged_at), "resolved_at": iso(i.resolved_at), "sla": sla_state(i),
            "tasks": i.tasks or [], "linked": i.linked or [], "stage": stage_of(i), "priority": priority_of(i), "priority_set": bool(i.priority),
            "tags": i.tags or [], "escalated_at": iso(i.escalated_at), "escalated_by": i.escalated_by, "escalated_to": i.escalated_to,
            "escalation_reason": i.escalation_reason}


@router.get("/incidents")
async def list_incidents(status: list[str] = Query(default=[]), severity: list[str] = Query(default=[]), assignee: str | None = None,
                         q: str | None = Query(None, max_length=128), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                         category: str = Query("security", pattern=r"^(security|wan|all)$"),
                         stage: list[str] = Query(default=[]), escalated: bool | None = None,
                         _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """category: security cases by default; ISP / WAN incidents live under /api/wan/incidents (category "wan")."""
    qy = select(Incident) if category == "all" else select(Incident).where(Incident.category == category)
    if stage:
        qy = qy.where(Incident.stage.in_(stage))
    if escalated is not None:
        qy = qy.where(Incident.escalated_at.is_not(None) if escalated else Incident.escalated_at.is_(None))
    if status:
        qy = qy.where(Incident.status.in_(status))
    if severity:
        qy = qy.where(Incident.severity.in_(severity))
    if assignee:
        qy = qy.where(Incident.assignee == assignee)
    if q:
        qy = qy.where(Incident.title.ilike(f"%{q}%") | Incident.entity.ilike(f"%{q}%"))
    total = (await s.execute(select(func.count()).select_from(qy.subquery()))).scalar_one()
    rows = (await s.execute(qy.order_by(Incident.status.in_(OPEN).desc(), Incident.last_seen.desc()).offset((page - 1) * size).limit(size))).scalars()
    cq = select(Incident.status, func.count()).group_by(Incident.status)
    counts = dict((await s.execute(cq if category == "all" else cq.where(Incident.category == category))).all())
    return {"items": [inc_out(i) for i in rows], "total": total, "status_counts": counts}


@router.get("/incidents/stats")
async def incident_stats(days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    incs = (await s.execute(select(Incident).where(Incident.created_at >= since, Incident.category == "security"))).scalars().all()
    closed = [i for i in incs if i.resolved_at]

    def hours(a, b):
        a = a if a.tzinfo else a.replace(tzinfo=timezone.utc)
        b = b if b.tzinfo else b.replace(tzinfo=timezone.utc)
        return (b - a).total_seconds() / 3600
    acked = [i for i in incs if i.acknowledged_at]
    return {"days": days, "total": len(incs),
            "open_by_severity": {sv: sum(1 for i in incs if i.status in OPEN and i.severity == sv) for sv in reversed(SEV)},
            "mtta_hours": round(sum(hours(i.created_at, i.acknowledged_at) for i in acked) / len(acked), 2) if acked else None,
            "mttr_hours": round(sum(hours(i.created_at, i.resolved_at) for i in closed) / len(closed), 2) if closed else None,
            "sla_ack_breaches": sum(1 for i in incs if sla_state(i)["ack_breached"]),
            "sla_resolve_breaches": sum(1 for i in incs if sla_state(i)["resolve_breached"]),
            "closure_reasons": {r: sum(1 for i in closed if i.closure_reason == r) for r in ("true_positive", "false_positive", "benign", "duplicate")}}


@router.get("/incidents/{iid}")
async def get_incident(iid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    alerts = (await s.execute(select(Alert).where(Alert.incident_id == iid).order_by(Alert.first_seen))).scalars().all()
    comments = (await s.execute(select(IncidentComment).where(IncidentComment.incident_id == iid).order_by(IncidentComment.ts))).scalars().all()
    timeline = sorted([{"ts": iso(a.first_seen), "kind": "alert", "title": a.name, "severity": a.severity, "ref": a.id,
                        "tactic": (a.mitre or {}).get("tactic_name")} for a in alerts] +
                      [{"ts": iso(c.ts), "kind": c.kind, "title": c.body, "author": c.author, "ref": c.id} for c in comments],
                      key=lambda x: x["ts"] or "")
    return {**inc_out(i), "alerts": [alert_out(a) for a in alerts],
            "comments": [{"id": c.id, "ts": iso(c.ts), "author": c.author, "kind": c.kind, "body": c.body} for c in comments],
            "timeline": timeline}


class IncidentPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(open|in_progress|resolved|closed)$")
    assignee: str | None = Field(None, max_length=64)
    summary: str | None = Field(None, max_length=10_000)
    closure_reason: str | None = Field(None, pattern=r"^(true_positive|false_positive|benign|duplicate)$")
    stage: str | None = Field(None, pattern=r"^(new|triage|investigation|containment|eradication|recovery|closed)$")
    priority: str | None = Field(None, pattern=r"^(P1|P2|P3|P4|)$")
    tags: list[str] | None = Field(None, max_length=20)


class EscalateIn(BaseModel):
    to: str = Field("", max_length=64)
    reason: str = Field(min_length=5, max_length=2000)


class FromAlertIn(BaseModel):
    note: str = Field("", max_length=2000)


@router.post("/incidents/from-alert/{alert_id}", status_code=201)
async def incident_from_alert(alert_id: int, body: FromAlertIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Open a security incident from one alert — the way a network (NMS) detection becomes a SIEM investigation."""
    from ..incidents import compute
    a = await s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "not found")
    if a.incident_id and (cur := await s.get(Incident, a.incident_id)):
        return inc_out(cur)
    ent_type, ent = ("ip", a.src_ip) if a.src_ip else ("ip", a.dst_ip) if a.dst_ip else ("firewall", str((a.firewall_ids or [0])[0]))
    inc = Incident(title=a.name, entity_type=ent_type, entity=ent or "unknown", status="open", category="security", alert_count=1, rule_keys=[a.rule_key],
                   first_seen=a.first_seen, last_seen=a.last_seen, severity=a.severity)
    s.add(inc)
    await s.flush()
    a.incident_id = inc.id
    compute(inc, [a])
    s.add(IncidentComment(incident_id=inc.id, author=user.username, kind="system",
                          body=f"Opened from alert #{a.id} ({a.rule_key})." + (f" {body.note}" if body.note else "")))
    await s.commit()
    await audit(s, request, user.username, "incident_from_alert", str(alert_id), {"incident": inc.id})
    return inc_out(inc)


@router.post("/incidents/{iid}/escalate")
async def escalate_incident(iid: int, body: EscalateIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    await escalate(s, i, user.username, body.to.strip(), body.reason.strip())
    await s.commit()
    await audit(s, request, user.username, "incident_escalate", str(iid), {"to": body.to})
    return inc_out(i)


@router.get("/incidents/{iid}/timeline")
async def incident_timeline(iid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """One ordered timeline: detections (first / last seen per alert), every status, stage, assignment and escalation
    change, comments, evidence and completed tasks."""
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    items = [{"at": iso(i.created_at), "kind": "created", "who": "system", "text": f"Incident opened: {i.title}"}]
    for a in (await s.execute(select(Alert).where(Alert.incident_id == iid).order_by(Alert.first_seen))).scalars():
        tech = ", ".join((a.mitre or {}).get("techniques") or [])
        items.append({"at": iso(a.first_seen), "kind": "detection", "who": a.rule_key, "alert_id": a.id, "severity": a.severity,
                      "text": f"{a.name}: {a.explanation}"[:500], "techniques": (a.mitre or {}).get("techniques") or [], "tactic": (a.mitre or {}).get("tactic_name", "")})
        if a.last_seen and a.last_seen != a.first_seen:
            items.append({"at": iso(a.last_seen), "kind": "detection_last", "who": a.rule_key, "alert_id": a.id,
                          "text": f"{a.name}: last matching event ({a.event_count} events in total)" + (f" [{tech}]" if tech else "")})
    for c in (await s.execute(select(IncidentComment).where(IncidentComment.incident_id == iid).order_by(IncidentComment.ts))).scalars():
        items.append({"at": iso(c.ts), "kind": c.kind, "who": c.author, "text": c.body[:2000]})
    for e in i.evidence or []:
        items.append({"at": e.get("at"), "kind": "evidence", "who": e.get("added_by", ""), "text": f"Evidence added: {e.get('label') or e.get('ref')}"})
    for t in i.tasks or []:
        if t.get("done") and t.get("done_at"):
            items.append({"at": t["done_at"], "kind": "task", "who": t.get("done_by", ""), "text": f"Task done: {t.get('text')}"})
    items = sorted((x for x in items if x.get("at")), key=lambda x: x["at"])
    return {"id": iid, "stage": stage_of(i), "items": items}


@router.patch("/incidents/{iid}")
async def update_incident(iid: int, body: IncidentPatch, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    data = body.model_dump(exclude_unset=True)
    if (data.get("status") in ("resolved", "closed") or data.get("stage") == "closed") and not (data.get("closure_reason") or i.closure_reason):
        raise HTTPException(422, "closure_reason is required to resolve or close an incident")
    if data.get("stage") and data["stage"] != stage_of(i):
        await set_stage(s, i, data["stage"], user.username, data.get("closure_reason"))
    elif "status" in data and data["status"] != i.status:
        await set_status(s, i, data["status"], user.username, data.get("closure_reason"))
    elif data.get("closure_reason"):
        i.closure_reason = data["closure_reason"]
    if "assignee" in data and data["assignee"] != i.assignee:
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status", body=f"Assigned to {data['assignee'] or 'nobody'}"))
        i.assignee = data["assignee"]
        if data["assignee"] and i.status == "open":
            await set_status(s, i, "in_progress", user.username)
    if "summary" in data:
        i.summary = data["summary"]
    if "priority" in data and data["priority"] != (i.priority or ""):
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status", body=f"Priority {priority_of(i)} → {data['priority'] or 'by severity'}"))
        i.priority = data["priority"] or ""
    if data.get("tags") is not None:
        i.tags = sorted({t.strip().lower()[:32] for t in data["tags"] if t and t.strip()})
    await s.commit()
    await audit(s, request, user.username, "incident_update", str(iid), data)
    return inc_out(i)


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


@router.post("/incidents/{iid}/comments", status_code=201)
async def add_comment(iid: int, body: CommentIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if not await s.get(Incident, iid):
        raise HTTPException(404, "not found")
    c = IncidentComment(incident_id=iid, author=user.username, kind="comment", body=body.body)
    s.add(c)
    await s.commit()
    return {"id": c.id, "ts": iso(c.ts), "author": c.author, "kind": c.kind, "body": c.body}


class EvidenceIn(BaseModel):
    type: str = Field(pattern=r"^(event|alert|link|note|ip)$")
    ref: str = Field(min_length=1, max_length=1024)
    label: str = Field("", max_length=255)


@router.post("/incidents/{iid}/evidence", status_code=201)
async def add_evidence(iid: int, body: EvidenceIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    if body.type == "link" and not body.ref.lower().startswith(("https://", "http://")):
        raise HTTPException(422, "links must start with http(s)://")
    item = {**body.model_dump(), "added_by": user.username, "at": datetime.now(timezone.utc).isoformat()}
    i.evidence = [*(i.evidence or []), item]
    s.add(IncidentComment(incident_id=iid, author=user.username, kind="evidence", body=f"Evidence added: {body.type} {body.label or body.ref}"))
    await s.commit()
    return item


class TaskIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)


class TaskPatch(BaseModel):
    done: bool


async def _incident(s: AsyncSession, iid: int) -> Incident:
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    return i


@router.post("/incidents/{iid}/tasks", status_code=201)
async def add_task(iid: int, body: TaskIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    import secrets
    i = await _incident(s, iid)
    if len(i.tasks or []) >= 50:
        raise HTTPException(422, "an incident holds at most 50 tasks")
    t = {"id": secrets.token_hex(4), "text": body.text.strip(), "done": False, "added_by": user.username}
    i.tasks = [*(i.tasks or []), t]
    await s.commit()
    return t


@router.patch("/incidents/{iid}/tasks/{tid}")
async def set_task(iid: int, tid: str, body: TaskPatch, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await _incident(s, iid)
    tasks = [dict(t) for t in (i.tasks or [])]
    t = next((x for x in tasks if x["id"] == tid), None)
    if not t:
        raise HTTPException(404, "task not found")
    t.update({"done": body.done, "done_by": user.username if body.done else None,
              "done_at": datetime.now(timezone.utc).isoformat() if body.done else None})
    i.tasks = tasks
    if body.done:
        s.add(IncidentComment(incident_id=iid, author=user.username, kind="status", body=f"Task done: {t['text']}"))
    await s.commit()
    return t


@router.delete("/incidents/{iid}/tasks/{tid}")
async def delete_task(iid: int, tid: str, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await _incident(s, iid)
    i.tasks = [t for t in (i.tasks or []) if t["id"] != tid]
    await s.commit()
    return {"ok": True}


class LinkIn(BaseModel):
    incident_id: int


@router.post("/incidents/{iid}/links")
async def link_incident(iid: int, body: LinkIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if body.incident_id == iid:
        raise HTTPException(422, "an incident cannot be linked to itself")
    a, b = await _incident(s, iid), await _incident(s, body.incident_id)
    a.linked = sorted(set(a.linked or []) | {b.id})
    b.linked = sorted(set(b.linked or []) | {a.id})
    s.add(IncidentComment(incident_id=a.id, author=user.username, kind="system", body=f"Linked to incident #{b.id}"))
    s.add(IncidentComment(incident_id=b.id, author=user.username, kind="system", body=f"Linked to incident #{a.id}"))
    await s.commit()
    return {"linked": a.linked}


@router.delete("/incidents/{iid}/links/{other}")
async def unlink_incident(iid: int, other: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await _incident(s, iid)
    a.linked = [x for x in (a.linked or []) if x != other]
    b = await s.get(Incident, other)
    if b:
        b.linked = [x for x in (b.linked or []) if x != iid]
    await s.commit()
    return {"linked": a.linked}


@router.get("/incident-analysts")
async def analyst_workload(days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Per-analyst queue and SLA performance (unassigned work appears as '(unassigned)')."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    now = datetime.now(timezone.utc)
    incs = (await s.execute(select(Incident).where((Incident.created_at >= since) | Incident.status.in_(OPEN)))).scalars().all()
    by: dict[str, dict] = {}
    for i in incs:
        k = i.assignee or "(unassigned)"
        r = by.setdefault(k, {"analyst": k, "open": 0, "in_progress": 0, "closed": 0, "critical_open": 0, "ack_breached": 0,
                              "resolve_breached": 0, "_ack": [], "_res": [], "tasks_open": 0})
        if i.status == "open":
            r["open"] += 1
        elif i.status == "in_progress":
            r["in_progress"] += 1
        else:
            r["closed"] += 1
        if i.status in OPEN and i.severity == "critical":
            r["critical_open"] += 1
        st = sla_state(i, now)
        r["ack_breached"] += st["ack_breached"]
        r["resolve_breached"] += st["resolve_breached"]
        created = i.created_at if i.created_at.tzinfo else i.created_at.replace(tzinfo=timezone.utc)
        if i.acknowledged_at:
            ack = i.acknowledged_at if i.acknowledged_at.tzinfo else i.acknowledged_at.replace(tzinfo=timezone.utc)
            r["_ack"].append((ack - created).total_seconds())
        if i.resolved_at:
            res = i.resolved_at if i.resolved_at.tzinfo else i.resolved_at.replace(tzinfo=timezone.utc)
            r["_res"].append((res - created).total_seconds())
        if i.status in OPEN:
            r["tasks_open"] += sum(1 for t in (i.tasks or []) if not t.get("done"))
    out = []
    for r in by.values():
        a, b = r.pop("_ack"), r.pop("_res")
        r["mtta_minutes"] = round(sum(a) / len(a) / 60, 1) if a else None
        r["mttr_hours"] = round(sum(b) / len(b) / 3600, 1) if b else None
        out.append(r)
    return sorted(out, key=lambda r: -(r["open"] + r["in_progress"]))


# ------------------------------------------------------------------ saved searches
class SearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    query: str = Field("", max_length=2000)
    range: str = Field("24h", pattern=r"^(5m|15m|1h|24h|7d|30d)$")
    shared: bool = True
    schedule: str = Field("none", pattern=r"^(none|hourly|daily)$")
    threshold: int = Field(1, ge=1, le=10_000_000)
    severity: str = Field("medium", pattern=r"^(informational|low|medium|high|critical)$")


def ss_out(x: SavedSearch) -> dict:
    return {"id": x.id, "name": x.name, "query": x.query, "range": x.range, "owner": x.owner, "shared": x.shared, "schedule": x.schedule,
            "threshold": x.threshold, "severity": x.severity, "last_run": iso(x.last_run), "last_count": x.last_count}


@router.post("/ql/validate")
async def ql_validate(body: dict, _: User = Depends(current_user)):
    try:
        compile_ql(str(body.get("query", "")))
        return {"valid": True}
    except QLError as e:
        return {"valid": False, "error": str(e), "pos": e.pos}


@router.get("/searches")
async def list_searches(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(SavedSearch).where((SavedSearch.shared.is_(True)) | (SavedSearch.owner == user.username))
                            .order_by(SavedSearch.name))).scalars()
    return [ss_out(x) for x in rows]


def _check(q: str):
    try:
        compile_ql(q)
    except QLError as e:
        raise HTTPException(422, str(e))


@router.post("/searches", status_code=201)
async def create_search(body: SearchIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    _check(body.query)
    if body.schedule != "none" and user.role != "admin":
        raise HTTPException(403, "only administrators can schedule searches")
    x = SavedSearch(**body.model_dump(), owner=user.username)
    s.add(x)
    await s.commit()
    await audit(s, request, user.username, "search_create", body.name)
    return ss_out(x)


@router.put("/searches/{sid}")
async def update_search(sid: int, body: SearchIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    x = await s.get(SavedSearch, sid)
    if not x:
        raise HTTPException(404, "not found")
    if x.owner != user.username and user.role != "admin":
        raise HTTPException(403, "only the owner or an administrator can edit this search")
    if body.schedule != "none" and user.role != "admin":
        raise HTTPException(403, "only administrators can schedule searches")
    _check(body.query)
    for k, v in body.model_dump().items():
        setattr(x, k, v)
    await s.commit()
    await audit(s, request, user.username, "search_update", body.name)
    return ss_out(x)


@router.delete("/searches/{sid}")
async def delete_search(sid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    x = await s.get(SavedSearch, sid)
    if not x:
        raise HTTPException(404, "not found")
    if x.owner != user.username and user.role != "admin":
        raise HTTPException(403, "only the owner or an administrator can delete this search")
    await s.delete(x)
    await s.commit()
    await audit(s, request, user.username, "search_delete", x.name)
    return {"ok": True}


@router.post("/searches/{sid}/run")
async def run_search(sid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    x = await s.get(SavedSearch, sid)
    if not x or not (x.shared or x.owner == user.username or user.role == "admin"):
        raise HTTPException(404, "not found")  # same answer as a missing id: private searches are not enumerable
    try:
        n = await count_matches(ch, x.query, x.range)
    except QLError as e:
        raise HTTPException(422, str(e))
    return {"count": n, "query": x.query, "range": x.range}
