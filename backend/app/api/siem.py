"""APIs: Sentinel Grid SOC analytics and response.

  /api/mitre/coverage, /api/mitre/techniques/{id}      ATT&CK coverage of the enabled rules and of recent alerts
  /api/network-security/*                             Zeek network analytics (overview, scans, beacons, DNS, TLS, ports, one connection)
  /api/risk/entities, /api/risk/{kind}/{entity}       explainable entity risk (hosts, users)
  /api/soc/metrics, /api/soc/executive                SOC operations (MTTD / MTTA / MTTR, SLA, workload) and the executive view
  /api/alerts/{id}/brief                              investigation brief of one alert (no AI involved)
  /api/ai/alerts/{id}/explain, /api/ai/hunts          optional AI narrative / hunt suggestions (validated, read-only)
  /api/response/*                                     response actions with approval, dry-run plan, verification, rollback
Everything reads stored data; nothing here changes a firewall, directory or host.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import investigate_brief, mitre, response, risk, socmetrics, zeek
from ..db.ch import ClickHouse
from ..db.models import Alert, AlertRule, Firewall, ResponseAction, User, Watchlist
from ..db.pg import get_session
from ..products import alert_product
from .deps import audit, ch_dep, current_user, iso

router = APIRouter(prefix="/api", tags=["siem"])
RANGE = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


def _win(range_: str) -> tuple[datetime, datetime]:
    if range_ not in RANGE:
        raise HTTPException(422, f"range is one of {', '.join(RANGE)}")
    t1 = datetime.now(timezone.utc)
    return t1 - RANGE[range_], t1


# ------------------------------------------------------------------ ATT&CK
@router.get("/mitre/coverage")
async def mitre_coverage(days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await mitre.coverage(s, lambda key: alert_product(key) == "grid", days)


@router.get("/mitre/techniques/{tid}")
async def mitre_technique(tid: str, days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    import re
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
        raise HTTPException(422, "technique ids look like T1110 or T1110.003")
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rules = [r for r in (await s.execute(select(AlertRule))).scalars() if tid in mitre.rule_techniques(r.mitre)]
    keys = [r.key for r in rules]
    alerts = (await s.execute(select(Alert).where(Alert.rule_key.in_(keys), Alert.last_seen >= since).order_by(Alert.last_seen.desc()).limit(100))).scalars().all() if keys else []
    return {**mitre.technique(tid), "rules": [{"key": r.key, "name": r.name, "enabled": r.enabled, "severity": r.severity} for r in rules],
            "alerts": [{"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "src_ip": a.src_ip, "last_seen": iso(a.last_seen),
                        "incident_id": a.incident_id, "disposition": a.disposition} for a in alerts]}


# ------------------------------------------------------------------ Zeek network analytics
@router.get("/network-security/overview")
async def ns_overview(range: str = "24h", _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await zeek.overview(ch, *_win(range))


@router.get("/network-security/scanners")
async def ns_scanners(range: str = "24h", min_ports: int = Query(30, ge=5, le=65535), min_hosts: int = Query(30, ge=5, le=100000),
                      _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return {"items": await zeek.scanners(ch, *_win(range), min_ports, min_hosts)}


@router.get("/network-security/beacons")
async def ns_beacons(range: str = "24h", min_conns: int = Query(12, ge=4, le=10000), max_cv: float = Query(0.35, gt=0, le=1),
                     _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return {"items": await zeek.beacons(ch, *_win(range), min_conns, max_cv)}


@router.get("/network-security/dns")
async def ns_dns(range: str = "24h", _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await zeek.dns(ch, *_win(range))


@router.get("/network-security/tls")
async def ns_tls(range: str = "24h", _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await zeek.tls(ch, *_win(range))


@router.get("/network-security/ports")
async def ns_ports(range: str = "24h", _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return {"items": await zeek.unusual_ports(ch, *_win(range))}


@router.get("/network-security/connection/{uid}")
async def ns_connection(uid: str, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    import re
    if not re.fullmatch(r"[A-Za-z0-9]{6,40}", uid):
        raise HTTPException(422, "not a Zeek connection uid")
    return await zeek.connection(ch, uid)


# ------------------------------------------------------------------ entity risk
@router.get("/risk/entities")
async def risk_entities(days: int = Query(30, ge=1, le=90), kind: str | None = Query(None, pattern="^(ip|user)$"), limit: int = Query(100, ge=1, le=500),
                        _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await risk.ranking(s, days, kind, limit)


@router.get("/risk/{kind}/{entity}")
async def risk_entity(kind: str, entity: str, days: int = Query(30, ge=1, le=90), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if kind not in ("ip", "user"):
        raise HTTPException(404, "kind is ip or user")
    return await risk.detail(s, kind, entity[:255], days)


# ------------------------------------------------------------------ SOC metrics
@router.get("/soc/metrics")
async def soc_metrics(days: int = Query(30, ge=1, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await socmetrics.operations(s, days)


@router.get("/soc/executive")
async def soc_executive(days: int = Query(7, ge=1, le=90), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    return await socmetrics.executive(s, ch, days)


# ------------------------------------------------------------------ investigation brief and AI
async def _alert(s: AsyncSession, aid: int) -> Alert:
    a = await s.get(Alert, aid)
    if not a:
        raise HTTPException(404, "not found")
    return a


@router.get("/alerts/{aid}/brief")
async def alert_brief(aid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await investigate_brief.build(s, ch, await _alert(s, aid))


@router.post("/ai/alerts/{aid}/explain")
async def ai_alert_explain(aid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                           ch: ClickHouse = Depends(ch_dep)):
    from .. import ai
    brief = await investigate_brief.build(s, ch, await _alert(s, aid))
    try:
        out = await ai.explain_alert(brief)
    except ai.AIError as e:
        raise HTTPException(503, str(e))
    await audit(s, request, user.username, "ai_alert_explain", str(aid))
    return {**out, "cited_events": [e["event_id"] for e in brief["evidence"]["events"]]}


@router.post("/ai/hunts")
async def ai_hunts(request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Hunting ideas from what the SIEM already knows (open detection names, techniques that fired, coverage gaps, TI
    categories). Only names and ids are sent, never events, addresses or users."""
    from .. import ai
    since = datetime.now(timezone.utc) - timedelta(days=14)
    rows = (await s.execute(select(Alert.name, Alert.mitre, func.count(Alert.id)).where(Alert.last_seen >= since).group_by(Alert.name, Alert.mitre)
                            .order_by(func.count(Alert.id).desc()).limit(40))).all()
    cov = await mitre.coverage(s, lambda key: alert_product(key) == "grid", 30)
    context = {"recent_detections": [{"name": n, "techniques": mitre.rule_techniques(m), "count": c} for n, m, c in rows],
               "coverage_gaps": [{"id": t["id"], "name": t["name"]} for t in cov["techniques"] if t["status"] == "gap"][:25]}
    wl = [w for (w,) in (await s.execute(select(Watchlist.name))).all()]
    try:
        out = await ai.suggest_hunts(context, wl)
    except ai.AIError as e:
        raise HTTPException(503, str(e))
    await audit(s, request, user.username, "ai_hunts", "", {"suggested": len(out["hunts"]), "dropped": len(out["dropped"])})
    return out


# ------------------------------------------------------------------ response actions
class ActionIn(BaseModel):
    kind: str = Field(pattern=r"^(block_ip|disable_account|isolate_host|enrich_ip|collect_evidence|notify)$")
    target: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=5, max_length=2000)
    incident_id: int | None = None
    alert_id: int | None = None
    firewall_ids: list[int] = Field(default_factory=list, max_length=50)
    hours: int | None = Field(None, ge=1, le=24 * 90)


class DecisionIn(BaseModel):
    approve: bool
    comment: str = Field("", max_length=2000)


class NoteIn(BaseModel):
    note: str = Field("", max_length=2000)


def _action_out(a: ResponseAction, user: User | None = None) -> dict:
    return {"id": a.id, "kind": a.kind, "target": a.target, "params": a.params, "reason": a.reason, "incident_id": a.incident_id, "alert_id": a.alert_id,
            "status": a.status, "requires_approval": a.requires_approval, "plan": a.plan, "result": a.result, "log": a.log,
            "requested_by": a.requested_by, "decided_by": a.decided_by, "decided_at": iso(a.decided_at), "decision_comment": a.decision_comment,
            "applied_by": a.applied_by, "applied_at": iso(a.applied_at), "expires_at": iso(a.expires_at), "created_at": iso(a.created_at),
            "can_decide": bool(user and a.status == "pending" and a.requires_approval and response.can_approve(user, a))}


async def _get(s: AsyncSession, rid: int) -> ResponseAction:
    a = await s.get(ResponseAction, rid)
    if not a:
        raise HTTPException(404, "not found")
    return a


@router.get("/response/actions")
async def list_actions(status: list[str] = Query(default=[]), incident_id: int | None = None, user: User = Depends(current_user),
                       s: AsyncSession = Depends(get_session)):
    q = select(ResponseAction)
    if status:
        q = q.where(ResponseAction.status.in_(status))
    if incident_id:
        q = q.where(ResponseAction.incident_id == incident_id)
    rows = (await s.execute(q.order_by(ResponseAction.created_at.desc()).limit(300))).scalars().all()
    counts = dict((await s.execute(select(ResponseAction.status, func.count()).group_by(ResponseAction.status))).all())
    fws = [{"id": f.id, "name": f.name, "vendor": f.vendor} for f in (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False)))).scalars()]
    return {"items": [_action_out(a, user) for a in rows], "counts": counts, "firewalls": fws,
            "actions": {"containment": list(response.CONTAINMENT), "read_only": list(response.READ_ONLY)}}


@router.post("/response/actions", status_code=201)
async def create_action(body: ActionIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    try:
        a, created = await response.request(s, user, body.kind, body.target, reason=body.reason, incident_id=body.incident_id, alert_id=body.alert_id,
                                            params={"firewall_ids": body.firewall_ids} if body.firewall_ids else {}, hours=body.hours)
        if created and not a.requires_approval:
            await response.run_read_only(s, ch, a)
    except response.ResponseError as e:
        raise HTTPException(422, str(e))
    await s.commit()
    if created:
        await audit(s, request, user.username, "response_request", f"{a.kind}:{a.target}", {"id": a.id, "incident_id": a.incident_id})
    return {**_action_out(a, user), "created": created}


@router.post("/response/actions/{rid}/decision")
async def decide_action(rid: int, body: DecisionIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await _get(s, rid)
    try:
        await response.decide(s, a, user, body.approve, body.comment)
    except response.ResponseError as e:
        await audit(s, request, user.username, "response_decision_refused", f"{a.kind}:{a.target}", {"id": a.id, "reason": str(e)}, success=False)
        raise HTTPException(403 if "second person" in str(e) else 409, str(e))
    await s.commit()
    await audit(s, request, user.username, "response_approve" if body.approve else "response_reject", f"{a.kind}:{a.target}", {"id": a.id})
    return _action_out(a, user)


@router.post("/response/actions/{rid}/applied")
async def applied_action(rid: int, body: NoteIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await _get(s, rid)
    try:
        await response.record_applied(s, a, user, body.note)
    except response.ResponseError as e:
        raise HTTPException(409, str(e))
    await s.commit()
    await audit(s, request, user.username, "response_applied", f"{a.kind}:{a.target}", {"id": a.id})
    return _action_out(a, user)


@router.post("/response/actions/{rid}/verify")
async def verify_action(rid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    a = await _get(s, rid)
    try:
        await response.verify(ch, a)
    except response.ResponseError as e:
        raise HTTPException(409, str(e))
    await s.commit()
    return _action_out(a, user)


@router.post("/response/actions/{rid}/rollback")
async def rollback_action(rid: int, body: NoteIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await _get(s, rid)
    try:
        await response.record_rollback(s, a, user, body.note)
    except response.ResponseError as e:
        raise HTTPException(409, str(e))
    await s.commit()
    await audit(s, request, user.username, "response_rollback", f"{a.kind}:{a.target}", {"id": a.id})
    return _action_out(a, user)


@router.post("/response/actions/{rid}/cancel")
async def cancel_action(rid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await _get(s, rid)
    if a.status not in ("pending", "approved"):
        raise HTTPException(409, f"action is {a.status}")
    if user.username != a.requested_by and user.role != "admin":
        raise HTTPException(403, "only the requester or an administrator can cancel")
    a.status = "cancelled"
    response._log(a, user.username, "cancelled")
    await s.commit()
    await audit(s, request, user.username, "response_cancel", f"{a.kind}:{a.target}", {"id": a.id})
    return _action_out(a, user)
