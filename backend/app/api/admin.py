from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import AuditLog, Firewall, RetentionPolicy, RetentionRun, User
from ..db.pg import get_session
from ..retention import list_partitions
from .deps import iso, audit, ch_dep, current_user, require_admin

router = APIRouter(prefix="/api", tags=["admin"])


@router.get("/system/status")
async def system_status(_: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep), s: AsyncSession = Depends(get_session)):
    srcs = await ch.aquery("SELECT source, count() AS events, max(ingest_time) AS last_ingest FROM events "
                           "WHERE event_time >= now() - INTERVAL 1 DAY GROUP BY source")
    demo_fw = (await s.execute(select(func.count(Firewall.id)).where(Firewall.is_demo.is_(True)))).scalar_one()
    return {"demo_mode": get_settings().demo_mode, "demo_firewalls": demo_fw,
            "sources_24h": [{**r, "last_ingest": str(r["last_ingest"])} for r in srcs]}


@router.get("/system/coverage")
async def data_coverage(_: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    """Per-category collection status so the UI can tell 'no matching events' apart from 'not collected'."""
    from ..analytics.queries import coverage
    return await coverage(ch)


@router.get("/admin/retention")
async def get_retention(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    pols = (await s.execute(select(RetentionPolicy).order_by(RetentionPolicy.category))).scalars()
    runs = (await s.execute(select(RetentionRun).order_by(RetentionRun.started_at.desc()).limit(50))).scalars()
    return {"policies": [{"category": p.category, "days": p.days, "enabled": p.enabled} for p in pols],
            "runs": [{"started_at": iso(r.started_at), "category": r.category, "cutoff": iso(r.cutoff),
                      "partitions_dropped": r.partitions_dropped, "rows_dropped": r.rows_dropped, "status": r.status,
                      "error": r.error} for r in runs]}


class RetentionIn(BaseModel):
    days: int = Field(ge=1, le=3650)
    enabled: bool = True


@router.put("/admin/retention/{category}")
async def set_retention(category: str, body: RetentionIn, request: Request, admin: User = Depends(require_admin),
                        s: AsyncSession = Depends(get_session)):
    p = await s.get(RetentionPolicy, category)
    if not p:
        raise HTTPException(404, "unknown category")
    old = {"days": p.days, "enabled": p.enabled}
    p.days, p.enabled = body.days, body.enabled
    await s.commit()
    await audit(s, request, admin.username, "retention_update", category, {"old": old, "new": body.model_dump()})
    return {"category": category, "days": p.days, "enabled": p.enabled}


@router.get("/admin/storage")
async def storage(_: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    parts = await list_partitions(ch)
    by_cat: dict[str, dict] = {}
    for p in parts:
        c = by_cat.setdefault(p["category"], {"category": p["category"], "rows": 0, "bytes": 0, "partitions": 0,
                                              "oldest_day": None, "newest_day": None})
        c["rows"] += p["rows"]
        c["bytes"] += p["bytes"]
        c["partitions"] += 1
        d = p["day"].date().isoformat()
        c["oldest_day"] = min(c["oldest_day"] or d, d)
        c["newest_day"] = max(c["newest_day"] or d, d)
    tables = await ch.aquery("SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes FROM system.parts "
                             "WHERE database = currentDatabase() AND active GROUP BY table ORDER BY bytes DESC")
    rate = await ch.aquery("SELECT toStartOfHour(minute) AS hour, sum(events) AS events FROM events_minute "
                           "WHERE minute >= now() - INTERVAL 24 HOUR GROUP BY hour ORDER BY hour")
    return {"categories": sorted(by_cat.values(), key=lambda x: x["category"]), "tables": tables,
            "ingest_per_hour": [{"hour": str(r["hour"]), "events": r["events"]} for r in rate]}


@router.get("/admin/audit")
async def audit_log(page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500), username: str | None = None,
                    action: str | None = None, _: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    q = select(AuditLog)
    if username:
        q = q.where(AuditLog.username == username)
    if action:
        q = q.where(AuditLog.action == action)
    rows = (await s.execute(q.order_by(AuditLog.ts.desc()).offset((page - 1) * size).limit(size))).scalars()
    return [{"ts": iso(r.ts), "username": r.username, "action": r.action, "target": r.target, "detail": r.detail,
             "client_ip": r.client_ip, "success": r.success} for r in rows]
