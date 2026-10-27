from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..alerts.rules import DEFAULT_RULES
from ..db.models import Alert, AlertRule, Suppression, User
from ..db.pg import get_session
from .deps import iso, audit, current_user, require_admin

router = APIRouter(prefix="/api", tags=["alerts"])
STATUSES = ("new", "investigating", "resolved", "suppressed")
SEVERITIES = ("critical", "high", "medium", "low", "informational")


def alert_out(a: Alert) -> dict:
    return {"id": a.id, "rule_key": a.rule_key, "name": a.name, "severity": a.severity, "status": a.status,
            "group_key": a.group_key, "src_ip": a.src_ip, "dst_ip": a.dst_ip, "firewall_ids": a.firewall_ids,
            "sites": a.sites, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
            "event_count": a.event_count, "explanation": a.explanation, "evidence": a.evidence,
            "event_filter": a.event_filter, "assignee": a.assignee, "notes": a.notes, "mitre": a.mitre or {},
            "incident_id": a.incident_id, "asset_criticality": a.asset_criticality, "base_severity": a.base_severity,
            "disposition": a.disposition}


@router.get("/alerts")
async def list_alerts(status: list[str] = Query(default=[]), severity: list[str] = Query(default=[]), rule_key: str | None = None,
                      src_ip: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                      _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(Alert)
    if status:
        q = q.where(Alert.status.in_(status))
    if severity:
        q = q.where(Alert.severity.in_(severity))
    if rule_key:
        q = q.where(Alert.rule_key == rule_key)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await s.execute(q.order_by(Alert.last_seen.desc()).offset((page - 1) * size).limit(size))).scalars()
    counts = dict((await s.execute(select(Alert.status, func.count()).group_by(Alert.status))).all())
    return {"items": [alert_out(a) for a in rows], "total": total, "status_counts": counts}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "not found")
    return alert_out(a)


class AlertPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(new|investigating|resolved|suppressed)$")
    notes: str | None = Field(None, max_length=10_000)
    assignee: str | None = Field(None, max_length=64)


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: int, body: AlertPatch, request: Request, user: User = Depends(current_user),
                       s: AsyncSession = Depends(get_session)):
    """Analysts may triage alerts (status/notes); this does not change any firewall."""
    a = await s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(a, k, v)
    await s.commit()
    await audit(s, request, user.username, "alert_update", str(alert_id), changes)
    return alert_out(a)


class SuppressIn(BaseModel):
    hours: int | None = Field(24, ge=1, le=24 * 365)
    reason: str = Field("", max_length=1000)


@router.post("/alerts/{alert_id}/suppress")
async def suppress(alert_id: int, body: SuppressIn, request: Request, user: User = Depends(require_admin),
                   s: AsyncSession = Depends(get_session)):
    a = await s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "not found")
    until = datetime.now(timezone.utc) + timedelta(hours=body.hours) if body.hours else None
    s.add(Suppression(rule_key=a.rule_key, group_key=a.group_key, until=until, reason=body.reason, created_by=user.username))
    a.status = "suppressed"
    await s.commit()
    await audit(s, request, user.username, "alert_suppress", str(alert_id), {"until": iso(until)})
    return alert_out(a)


@router.get("/alert-rules")
async def rules(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return [{"key": r.key, "name": r.name, "description": r.description, "severity": r.severity, "enabled": r.enabled,
             "params": r.params, "mitre": r.mitre or {}} for r in (await s.execute(select(AlertRule).order_by(AlertRule.key))).scalars()]


class RuleIn(BaseModel):
    enabled: bool | None = None
    severity: str | None = Field(None, pattern=r"^(critical|high|medium|low|informational)$")
    params: dict | None = None


@router.put("/alert-rules/{key}")
async def update_rule(key: str, body: RuleIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = (await s.execute(select(AlertRule).where(AlertRule.key == key))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "not found")
    if body.params is not None:
        defaults = next(d["params"] for d in DEFAULT_RULES if d["key"] == key)
        unknown = set(body.params) - set(defaults)
        if unknown:
            raise HTTPException(422, f"unknown parameters: {sorted(unknown)}")
        for k, v in body.params.items():
            if type(defaults[k]) in (int, float) and not isinstance(v, (int, float)):
                raise HTTPException(422, f"{k} must be numeric")
            if isinstance(defaults[k], list) and not isinstance(v, list):
                raise HTTPException(422, f"{k} must be a list")
            if isinstance(v, (int, float)) and v < 0:
                raise HTTPException(422, f"{k} must be >= 0")
        r.params = {**r.params, **body.params}
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.severity:
        r.severity = body.severity
    await s.commit()
    await audit(s, request, admin.username, "rule_update", key, body.model_dump(exclude_unset=True))
    return {"key": r.key, "enabled": r.enabled, "severity": r.severity, "params": r.params}
