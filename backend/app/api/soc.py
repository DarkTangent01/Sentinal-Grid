"""APIs: incidents/cases, rule effectiveness, notifications, saved searches, reports."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.ql import QLError, compile_ql
from ..db.ch import ClickHouse
from ..db.models import (Alert, AlertRule, Incident, IncidentComment, NotificationChannel, NotificationOutbox, NotificationRule,
                         ReportDefinition, ReportRun, SavedSearch, User)
from ..db.pg import get_session
from ..incidents import OPEN, SEV, sla_state, set_status
from ..netguard import DestinationError, check_host_static, check_url_static
from ..notify import EVENT_TYPES, deliver, seal, secrets_of
from ..reports import SECTIONS, run_definition
from ..searches import count_matches
from .alerts import alert_out
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["soc"])


# ------------------------------------------------------------------ incidents / cases
def inc_out(i: Incident) -> dict:
    return {"id": i.id, "title": i.title, "entity_type": i.entity_type, "entity": i.entity, "status": i.status, "severity": i.severity,
            "score": i.score, "tactics": i.tactics, "techniques": i.techniques, "rule_keys": i.rule_keys, "alert_count": i.alert_count,
            "asset_criticality": i.asset_criticality, "assignee": i.assignee, "summary": i.summary, "closure_reason": i.closure_reason,
            "evidence": i.evidence, "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "created_at": iso(i.created_at),
            "acknowledged_at": iso(i.acknowledged_at), "resolved_at": iso(i.resolved_at), "sla": sla_state(i),
            "tasks": i.tasks or [], "linked": i.linked or []}


@router.get("/incidents")
async def list_incidents(status: list[str] = Query(default=[]), severity: list[str] = Query(default=[]), assignee: str | None = None,
                         q: str | None = Query(None, max_length=128), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                         _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(Incident)
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
    counts = dict((await s.execute(select(Incident.status, func.count()).group_by(Incident.status))).all())
    return {"items": [inc_out(i) for i in rows], "total": total, "status_counts": counts}


@router.get("/incidents/stats")
async def incident_stats(days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    incs = (await s.execute(select(Incident).where(Incident.created_at >= since))).scalars().all()
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


@router.patch("/incidents/{iid}")
async def update_incident(iid: int, body: IncidentPatch, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await s.get(Incident, iid)
    if not i:
        raise HTTPException(404, "not found")
    data = body.model_dump(exclude_unset=True)
    if data.get("status") in ("resolved", "closed") and not (data.get("closure_reason") or i.closure_reason):
        raise HTTPException(422, "closure_reason is required to resolve or close an incident")
    if "status" in data and data["status"] != i.status:
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


@router.get("/alert-rules/stats")
async def rule_stats(days: int = Query(90, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await s.execute(select(Alert.rule_key, Alert.disposition, func.count()).where(Alert.created_at >= since)
                            .group_by(Alert.rule_key, Alert.disposition))).all()
    out: dict = {}
    for key, disp, n in rows:
        r = out.setdefault(key, {"rule_key": key, "alerts": 0, "true_positive": 0, "false_positive": 0, "benign": 0, "undetermined": 0})
        r["alerts"] += n
        r[disp if disp in ("true_positive", "false_positive", "benign") else "undetermined"] += n
    for r in out.values():
        decided = r["true_positive"] + r["false_positive"] + r["benign"]
        r["false_positive_rate"] = round(r["false_positive"] / decided, 3) if decided else None
    names = {x.key: x.name for x in (await s.execute(select(AlertRule))).scalars()}
    return sorted(({**r, "name": names.get(k, k)} for k, r in out.items()), key=lambda r: -(r["false_positive_rate"] or 0))


# ------------------------------------------------------------------ notifications
def ch_out(c: NotificationChannel) -> dict:
    sec = secrets_of(c)
    return {"id": c.id, "name": c.name, "type": c.type, "config": c.config, "enabled": c.enabled,
            "has_secret": bool(sec), "secret_fields": sorted(sec)}  # secret values are never returned


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    type: str = Field(pattern=r"^(email|slack|teams|webhook)$")
    config: dict = Field(default_factory=dict)  # email: host, port, security, username, from_addr, to[]
    url: str | None = Field(None, max_length=2048)  # slack/teams/webhook (stored encrypted)
    password: str | None = Field(None, max_length=512)  # SMTP (stored encrypted)
    hmac_secret: str | None = Field(None, max_length=512)  # webhook signing (stored encrypted)
    enabled: bool = True


def _validate_channel(body: ChannelIn, existing_secret: dict) -> dict:
    secret = {**existing_secret, **{k: v for k, v in (("url", body.url), ("password", body.password), ("hmac_secret", body.hmac_secret)) if v}}
    if body.type in ("slack", "teams", "webhook") and not str(secret.get("url", "")).lower().startswith(("https://", "http://")):
        raise HTTPException(422, "a webhook URL (https://...) is required")
    try:
        if body.type in ("slack", "teams", "webhook"):
            check_url_static(str(secret["url"]), ("https", "http"))
        elif body.type == "email" and body.config.get("host"):
            check_host_static(str(body.config["host"]))
    except DestinationError as e:
        raise HTTPException(422, str(e))
    if body.type == "email":
        cfg = body.config
        if not cfg.get("host") or not cfg.get("to"):
            raise HTTPException(422, "SMTP host and at least one recipient are required")
        if cfg.get("security", "starttls") not in ("starttls", "ssl", "none"):
            raise HTTPException(422, "security must be starttls, ssl or none")
    return secret


@router.get("/notifications/channels")
async def list_channels(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    return [ch_out(c) for c in (await s.execute(select(NotificationChannel).order_by(NotificationChannel.name))).scalars()]


@router.post("/notifications/channels", status_code=201)
async def create_channel(body: ChannelIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    secret = _validate_channel(body, {})
    c = NotificationChannel(name=body.name, type=body.type, config=body.config, secret_ciphertext=seal(secret), enabled=body.enabled)
    s.add(c)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_create", body.name, {"type": body.type})
    return ch_out(c)


@router.put("/notifications/channels/{cid}")
async def update_channel(cid: int, body: ChannelIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    secret = _validate_channel(body, secrets_of(c))
    c.name, c.type, c.config, c.enabled, c.secret_ciphertext = body.name, body.type, body.config, body.enabled, seal(secret)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_update", body.name)
    return ch_out(c)


@router.delete("/notifications/channels/{cid}")
async def delete_channel(cid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    await s.delete(c)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_delete", c.name)
    return {"ok": True}


@router.post("/notifications/channels/{cid}/test")
async def test_channel(cid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    payload = {"title": "Sentinel Grid test notification", "text": f"Test message sent by {admin.username}.",
               "severity": "informational", "fields": {"Channel": c.name}, "event_type": "test"}
    try:
        await deliver(c, payload)
        ok, err = True, None
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"[:300]
    await audit(s, request, admin.username, "notify_channel_test", c.name, {"ok": ok}, success=ok)
    return {"ok": ok, "error": err}


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    channel_id: int
    event_types: list[str] = Field(min_length=1)
    min_severity: str = Field("high", pattern=r"^(informational|low|medium|high|critical)$")
    rule_keys: list[str] = Field(default_factory=list)
    quiet_start: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    quiet_end: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    quiet_tz: str = Field("UTC", max_length=64)
    dedupe_minutes: int = Field(30, ge=0, le=1440)
    enabled: bool = True


def nr_out(r: NotificationRule) -> dict:
    return {k: getattr(r, k) for k in ("id", "name", "channel_id", "event_types", "min_severity", "rule_keys", "quiet_start", "quiet_end",
                                       "quiet_tz", "dedupe_minutes", "enabled")}


@router.get("/notifications/rules")
async def list_nrules(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    return {"rules": [nr_out(r) for r in (await s.execute(select(NotificationRule).order_by(NotificationRule.id))).scalars()],
            "event_types": list(EVENT_TYPES)}


async def _save_rule(s, r: NotificationRule, body: RuleIn):
    bad = set(body.event_types) - set(EVENT_TYPES)
    if bad:
        raise HTTPException(422, f"unknown event types {sorted(bad)}")
    if not await s.get(NotificationChannel, body.channel_id):
        raise HTTPException(422, "channel not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)


@router.post("/notifications/rules", status_code=201)
async def create_nrule(body: RuleIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = NotificationRule()
    await _save_rule(s, r, body)
    s.add(r)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_create", body.name)
    return nr_out(r)


@router.put("/notifications/rules/{rid}")
async def update_nrule(rid: int, body: RuleIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(NotificationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await _save_rule(s, r, body)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_update", body.name)
    return nr_out(r)


@router.delete("/notifications/rules/{rid}")
async def delete_nrule(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(NotificationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_delete", r.name)
    return {"ok": True}


@router.get("/notifications/log")
async def notify_log(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(NotificationOutbox).order_by(NotificationOutbox.id.desc()).limit(200))).scalars()
    return [{"id": o.id, "created_at": iso(o.created_at), "channel_id": o.channel_id, "rule_id": o.rule_id, "event_type": o.event_type,
             "title": (o.payload or {}).get("title"), "severity": (o.payload or {}).get("severity"), "status": o.status,
             "attempts": o.attempts, "sent_at": iso(o.sent_at), "error": o.error} for o in rows]


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


# ------------------------------------------------------------------ reports
class ReportIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    period: str = Field("daily", pattern=r"^(daily|weekly|monthly)$")
    sections: list[str] = Field(default_factory=lambda: list(SECTIONS))
    channel_ids: list[int] = Field(default_factory=list)
    enabled: bool = True
    send_hour: int = Field(7, ge=0, le=23)
    tz: str = Field("UTC", max_length=64)


def rd_out(d: ReportDefinition) -> dict:
    return {"id": d.id, "name": d.name, "period": d.period, "sections": d.sections, "channel_ids": d.channel_ids, "enabled": d.enabled,
            "send_hour": d.send_hour, "tz": d.tz, "last_run": iso(d.last_run), "created_by": d.created_by}


@router.get("/reports")
async def list_reports(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    defs = (await s.execute(select(ReportDefinition).order_by(ReportDefinition.name))).scalars()
    runs = (await s.execute(select(ReportRun).order_by(ReportRun.generated_at.desc()).limit(50))).scalars()
    return {"definitions": [rd_out(d) for d in defs], "sections": SECTIONS,
            "runs": [{"id": r.id, "name": r.name, "generated_at": iso(r.generated_at), "period_start": iso(r.period_start),
                      "period_end": iso(r.period_end), "summary": r.summary} for r in runs]}


async def _save_def(d: ReportDefinition, body: ReportIn):
    bad = set(body.sections) - set(SECTIONS)
    if bad:
        raise HTTPException(422, f"unknown sections {sorted(bad)}")
    for k, v in body.model_dump().items():
        setattr(d, k, v)


@router.post("/reports", status_code=201)
async def create_report(body: ReportIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = ReportDefinition(created_by=admin.username)
    await _save_def(d, body)
    s.add(d)
    await s.commit()
    await audit(s, request, admin.username, "report_create", body.name)
    return rd_out(d)


@router.put("/reports/{rid}")
async def update_report(rid: int, body: ReportIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    await _save_def(d, body)
    await s.commit()
    await audit(s, request, admin.username, "report_update", body.name)
    return rd_out(d)


@router.delete("/reports/{rid}")
async def delete_report(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    await s.delete(d)
    await s.commit()
    await audit(s, request, admin.username, "report_delete", d.name)
    return {"ok": True}


@router.post("/reports/{rid}/run")
async def run_report(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session),
                     ch: ClickHouse = Depends(ch_dep)):
    d = await s.get(ReportDefinition, rid)
    if not d:
        raise HTTPException(404, "not found")
    run = await run_definition(s, ch, d)
    await audit(s, request, admin.username, "report_run", d.name)
    return {"id": run.id}


@router.get("/reports/runs/{run_id}.html", response_class=HTMLResponse)
async def report_html(run_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    r = await s.get(ReportRun, run_id)
    if not r:
        raise HTTPException(404, "not found")
    # static document: no scripts allowed
    return HTMLResponse(r.html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
