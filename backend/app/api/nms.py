"""APIs: Sentinel NMS core — network analytics, service checks, maintenance windows and device dependencies
(docs/NMS.md). Analytics and lists are read-only for every NMS user; changes need the administrator role and are
audited. Service checks only probe targets an administrator registered; TLS certificates are always verified."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import NmsMaintenance, NmsService, Switch, User
from ..db.pg import get_session
from ..nms import analytics as A
from ..nms import maintenance as MW
from ..nms import services as SV
from .deps import audit, ch_dep, current_user, require_admin

router = APIRouter(prefix="/api/nms", tags=["nms"])
NAME = r"^[A-Za-z0-9][A-Za-z0-9 ._:/()\-]{0,127}$"
RANGE = r"^(24h|7d|30d|90d)$"


def _now():
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ analytics
class Scope:
    def __init__(self, site: str | None = Query(None, max_length=128), vendor: str | None = Query(None, max_length=16),
                 role: str | None = Query(None, max_length=32)):
        self.kw = {"site": site, "vendor": vendor, "role": role}


@router.get("/analytics/availability")
async def availability(range: str = Query("30d", pattern=RANGE), sla: float = Query(99.9, ge=90, le=100), sc: Scope = Depends(),
                       _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await A.availability(s, ch, range_=range, sla=sla, **sc.kw)


@router.get("/analytics/capacity")
async def capacity(days: int = Query(30, ge=7, le=90), interface_threshold: float = Query(80, ge=10, le=100),
                   device_threshold: float = Query(90, ge=10, le=100), limit: int = Query(100, ge=1, le=500), sc: Scope = Depends(),
                   _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await A.capacity(s, ch, days=days, threshold_if=interface_threshold, threshold_dev=device_threshold, limit=limit, **sc.kw)


@router.get("/analytics/top/interfaces")
async def top_interfaces(range: str = Query("24h", pattern=RANGE), by: str = Query("peak_util", pattern=r"^(peak_util|avg_util|traffic|errors|discards|down|p95)$"),
                         limit: int = Query(20, ge=1, le=200), sc: Scope = Depends(), _: User = Depends(current_user),
                         s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await A.top_interfaces(s, ch, range_=range, by=by, limit=limit, **sc.kw)


@router.get("/analytics/top/devices")
async def top_devices(range: str = Query("24h", pattern=RANGE), by: str = Query("cpu", pattern=r"^(cpu|memory|temperature|storage|poll_time)$"),
                      limit: int = Query(20, ge=1, le=200), sc: Scope = Depends(), _: User = Depends(current_user),
                      s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await A.top_devices(s, ch, range_=range, by=by, limit=limit, **sc.kw)


@router.get("/analytics/health")
async def health(sc: Scope = Depends(), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await A.health(s, **sc.kw)


@router.get("/analytics/inventory")
async def inventory(unused_days: int = Query(30, ge=1, le=365), sc: Scope = Depends(), _: User = Depends(current_user),
                    s: AsyncSession = Depends(get_session)):
    return await A.inventory(s, unused_days=unused_days, **sc.kw)


@router.get("/analytics/alerts")
async def alerts(range: str = Query("7d", pattern=RANGE), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await A.alert_analytics(s, range_=range)


@router.get("/analytics/filters")
async def filters(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    sws = (await s.execute(select(Switch))).scalars().all()
    return {"sites": sorted({x.site for x in sws if x.site}), "vendors": sorted({x.vendor for x in sws if x.vendor}),
            "roles": sorted({x.role for x in sws if x.role})}


# ------------------------------------------------------------------ service checks
class ServiceIn(BaseModel):
    name: str = Field(pattern=NAME)
    kind: str = Field(pattern=r"^(tcp|http|dns|tls)$")
    target: str = Field(min_length=1, max_length=255)
    port: int | None = Field(None, ge=1, le=65535)
    expect: str = Field("", max_length=64)
    match: str = Field("", max_length=255)
    record: str = Field("A", pattern=r"^(A|AAAA)$")
    switch_id: int | None = None
    site: str = Field("", max_length=128)
    interval_seconds: int = Field(60, ge=30, le=86400)
    timeout_ms: int = Field(5000, ge=500, le=60000)
    latency_warn_ms: int | None = Field(None, ge=1, le=600000)
    cert_warn_days: int = Field(21, ge=1, le=365)
    enabled: bool = True


async def _svc_validated(s: AsyncSession, body: ServiceIn, sid: int | None = None) -> None:
    try:
        SV.validate(body.kind, body.target.strip(), body.port, body.expect, body.record)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.switch_id is not None and await s.get(Switch, body.switch_id) is None:
        raise HTTPException(422, "device not found")
    other = (await s.execute(select(NmsService).where(NmsService.name == body.name))).scalars().first()
    if other and other.id != sid:
        raise HTTPException(409, "another service check already uses this name")


def _svc_apply(svc: NmsService, body: ServiceIn):
    for k in ("name", "kind", "port", "expect", "match", "record", "switch_id", "site", "interval_seconds", "timeout_ms", "latency_warn_ms",
              "cert_warn_days", "enabled"):
        setattr(svc, k, getattr(body, k))
    svc.target = body.target.strip()


async def _names(s: AsyncSession) -> dict[int, str]:
    return {i: n for i, n in (await s.execute(select(Switch.id, Switch.name))).all()}


@router.get("/services")
async def list_services(state: str | None = Query(None, pattern=r"^(ok|warning|critical|unknown|paused)$"), q: str | None = Query(None, max_length=128),
                        _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = _now()
    names = await _names(s)
    rows = [SV.row(x, now, names) for x in (await s.execute(select(NmsService).order_by(NmsService.name))).scalars()]
    counts = {k: sum(1 for r in rows if r["state"] == k) for k in ("ok", "warning", "critical", "unknown", "paused")}
    if state:
        rows = [r for r in rows if r["state"] == state]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["name"].lower() or ql in r["target"].lower() or ql in (r["site"] or "").lower()]
    return {"items": rows, "counts": counts, "total": sum(counts.values())}


@router.get("/services/{sid}/history")
async def service_history(sid: int, range: str = Query("24h", pattern=RANGE), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                          ch: ClickHouse = Depends(ch_dep)):
    svc = await s.get(NmsService, sid)
    if svc is None:
        raise HTTPException(404, "service check not found")
    t0, _t1 = A.window(range, _now())
    step = {"24h": 300, "7d": 3600, "30d": 4 * 3600, "90d": 12 * 3600}[range]
    rows = await ch.aquery(
        "SELECT toStartOfInterval(ts, toIntervalSecond({step:UInt32})) AS t, avg(latency_ms) AS lat, max(latency_ms) AS lat_max, count() AS n, "
        "countIf(state = 'critical') AS crit, countIf(state = 'warning') AS warn FROM service_results "
        "WHERE service_id = {id:UInt32} AND ts >= {t0:DateTime64(3)} GROUP BY t ORDER BY t", {"step": step, "id": sid, "t0": t0})
    recent = await ch.aquery("SELECT ts, state, latency_ms, message FROM service_results WHERE service_id = {id:UInt32} "
                             "AND state != 'ok' AND ts >= {t0:DateTime64(3)} ORDER BY ts DESC LIMIT 50", {"id": sid, "t0": t0})
    n = sum(int(r["n"]) for r in rows)
    bad = sum(int(r["crit"]) for r in rows)
    return {"service": SV.row(svc, _now(), await _names(s)), "range": range, "step_seconds": step,
            "availability_pct": round(100.0 * (n - bad) / n, 3) if n else None, "checks": n,
            "series": [{"t": A._iso(r["t"]) if not isinstance(r["t"], str) else r["t"], "latency_ms": A._r(r["lat"], 1), "latency_max_ms": A._r(r["lat_max"], 1),
                        "checks": int(r["n"]), "critical": int(r["crit"]), "warning": int(r["warn"])} for r in rows],
            "failures": [{"ts": r["ts"] if isinstance(r["ts"], str) else A._iso(r["ts"]), "state": r["state"], "latency_ms": A._r(r["latency_ms"], 1),
                          "message": r["message"]} for r in recent]}


@router.post("/services", status_code=201)
async def create_service(body: ServiceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    await _svc_validated(s, body)
    svc = NmsService(created_by=user.username, state="unknown", fail_streak=0, last_message="")
    _svc_apply(svc, body)
    s.add(svc)
    await s.commit()
    await audit(s, request, user.username, "nms_service_create", svc.name, {"kind": svc.kind, "target": svc.target, "port": svc.port})
    await s.commit()
    return {"id": svc.id}


@router.put("/services/{sid}")
async def update_service(sid: int, body: ServiceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    svc = await s.get(NmsService, sid)
    if svc is None:
        raise HTTPException(404, "service check not found")
    await _svc_validated(s, body, sid)
    target_changed = (body.kind, body.target.strip(), body.port) != (svc.kind, svc.target, svc.port)
    _svc_apply(svc, body)
    if target_changed:
        svc.state, svc.state_since, svc.fail_streak, svc.cert_expires_at, svc.last_latency_ms = "unknown", None, 0, None, None
    await s.commit()
    await audit(s, request, user.username, "nms_service_update", svc.name, {"kind": svc.kind, "target": svc.target, "port": svc.port})
    await s.commit()
    return {"id": svc.id}


@router.delete("/services/{sid}")
async def delete_service(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    svc = await s.get(NmsService, sid)
    if svc is None:
        raise HTTPException(404, "service check not found")
    await s.delete(svc)
    await s.commit()
    await audit(s, request, user.username, "nms_service_delete", svc.name)
    await s.commit()
    return {"ok": True}


@router.post("/services/{sid}/run")
async def run_service(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session),
                      ch: ClickHouse = Depends(ch_dep)):
    """Run one check now (same probe as the worker) and record the result."""
    svc = await s.get(NmsService, sid)
    if svc is None:
        raise HTTPException(404, "service check not found")
    now = _now()
    r = await SV.run_check(svc, now)
    SV.apply(svc, r, now)
    await s.commit()
    try:
        await ch.ainsert("service_results", [{"ts": now.replace(microsecond=0), "service_id": svc.id, "state": r.state, "latency_ms": r.latency_ms,
                                              "message": r.message[:500]}], SV.RESULT_COLS)
    except Exception:
        pass
    await audit(s, request, user.username, "nms_service_run", svc.name, {"state": r.state})
    await s.commit()
    return SV.row(svc, now, await _names(s))


# ------------------------------------------------------------------ maintenance windows
class MaintenanceIn(BaseModel):
    name: str = Field(pattern=NAME)
    reason: str = Field("", max_length=2000)
    kind: str = Field("once", pattern=r"^(once|weekly)$")
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    weekdays: list[int] = Field(default_factory=list)
    start_time: str = Field("", max_length=5)
    duration_minutes: int = Field(60, ge=1, le=7 * 1440)
    timezone: str = Field("UTC", max_length=64)
    all_devices: bool = False
    switch_ids: list[int] = Field(default_factory=list, max_length=2000)
    sites: list[str] = Field(default_factory=list, max_length=200)
    service_ids: list[int] = Field(default_factory=list, max_length=2000)
    enabled: bool = True

    @field_validator("weekdays")
    @classmethod
    def _wd(cls, v):
        if any(d not in range(7) for d in v):
            raise ValueError("weekdays are 0 (Monday) to 6 (Sunday)")
        return sorted(set(v))

    @field_validator("sites")
    @classmethod
    def _sites(cls, v):
        return [x.strip()[:128] for x in v if x.strip()]


def _mw_check(body: MaintenanceIn):
    try:
        MW.zone(body.timezone)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.kind == "once":
        if not body.starts_at or not body.ends_at:
            raise HTTPException(422, "a one-off window needs a start and an end")
        a = body.starts_at if body.starts_at.tzinfo else body.starts_at.replace(tzinfo=timezone.utc)
        b = body.ends_at if body.ends_at.tzinfo else body.ends_at.replace(tzinfo=timezone.utc)
        if b <= a:
            raise HTTPException(422, "the window must end after it starts")
        if b - a > timedelta(days=31):
            raise HTTPException(422, "a one-off window can last at most 31 days")
    else:
        if not body.weekdays or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", body.start_time or ""):
            raise HTTPException(422, "a weekly window needs weekdays and a start time (HH:MM)")
    if not (body.all_devices or body.switch_ids or body.sites or body.service_ids):
        raise HTTPException(422, "choose the devices, sites or service checks the window covers (or all devices)")


def _mw_apply(m: NmsMaintenance, body: MaintenanceIn):
    for k in ("name", "reason", "kind", "weekdays", "start_time", "duration_minutes", "timezone", "all_devices", "switch_ids", "sites",
              "service_ids", "enabled"):
        setattr(m, k, getattr(body, k))
    m.starts_at = body.starts_at if body.kind == "once" else None
    m.ends_at = body.ends_at if body.kind == "once" else None


@router.get("/maintenance")
async def list_maintenance(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = _now()
    rows = [MW.row(m, now) for m in (await s.execute(select(NmsMaintenance).order_by(NmsMaintenance.id.desc()))).scalars()]
    return {"items": rows, "active": sum(1 for r in rows if r["active"])}


@router.post("/maintenance", status_code=201)
async def create_maintenance(body: MaintenanceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    _mw_check(body)
    m = NmsMaintenance(created_by=user.username)
    _mw_apply(m, body)
    s.add(m)
    await s.commit()
    await audit(s, request, user.username, "nms_maintenance_create", m.name, {"kind": m.kind, "all": m.all_devices, "devices": len(m.switch_ids),
                                                                              "sites": m.sites})
    await s.commit()
    return {"id": m.id}


@router.put("/maintenance/{mid}")
async def update_maintenance(mid: int, body: MaintenanceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(NmsMaintenance, mid)
    if m is None:
        raise HTTPException(404, "maintenance window not found")
    _mw_check(body)
    _mw_apply(m, body)
    await s.commit()
    await audit(s, request, user.username, "nms_maintenance_update", m.name)
    await s.commit()
    return {"id": m.id}


@router.delete("/maintenance/{mid}")
async def delete_maintenance(mid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(NmsMaintenance, mid)
    if m is None:
        raise HTTPException(404, "maintenance window not found")
    await s.delete(m)
    await s.commit()
    await audit(s, request, user.username, "nms_maintenance_delete", m.name)
    await s.commit()
    return {"ok": True}


# ------------------------------------------------------------------ device dependencies
class ParentIn(BaseModel):
    parent_id: int | None = None


@router.get("/dependencies")
async def dependencies(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    sws = (await s.execute(select(Switch).order_by(Switch.name))).scalars().all()
    by = {x.id: x for x in sws}
    children: dict[int, int] = {}
    for x in sws:
        if x.parent_id:
            children[x.parent_id] = children.get(x.parent_id, 0) + 1
    return {"items": [{"id": x.id, "name": x.name, "site": x.site, "role": x.role, "state": x.state, "parent_id": x.parent_id,
                       "parent": by[x.parent_id].name if x.parent_id in by else None, "children": children.get(x.id, 0)} for x in sws]}


@router.put("/dependencies/{sid}")
async def set_parent(sid: int, body: ParentIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await s.get(Switch, sid)
    if sw is None:
        raise HTTPException(404, "device not found")
    if body.parent_id is not None:
        if body.parent_id == sid:
            raise HTTPException(422, "a device cannot depend on itself")
        by = {x.id: x for x in (await s.execute(select(Switch))).scalars()}
        if body.parent_id not in by:
            raise HTTPException(422, "parent device not found")
        cur, seen = by.get(body.parent_id), set()
        while cur is not None and cur.id not in seen:
            if cur.id == sid:
                raise HTTPException(422, "this would create a dependency loop")
            seen.add(cur.id)
            cur = by.get(cur.parent_id)
    old = sw.parent_id
    sw.parent_id = body.parent_id
    await s.commit()
    await audit(s, request, user.username, "nms_dependency_set", sw.name, {"before": old, "after": body.parent_id})
    await s.commit()
    return {"id": sw.id, "parent_id": sw.parent_id}
