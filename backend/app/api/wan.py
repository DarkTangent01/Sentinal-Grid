"""APIs: WAN observability — overview, live ISP monitoring, circuit inventory, outages, ISP incidents, analytics,
investigation, maintenance and settings (docs/WAN.md). Reads need a signed-in user; configuration needs the admin role;
incident workflow (status, owner, root cause, comments) is open to analysts like security incidents. The existing
/api/isp endpoints (SD-WAN analytics, ICMP target CRUD) are unchanged."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import icmp, wan, wan_metrics as WM
from ..db.ch import ClickHouse
from ..db.models import (Firewall, IcmpEvent, IcmpTarget, Incident, IncidentComment, IspLink, User, WanMaintenance, WanOutage)
from ..db.pg import get_session
from .deps import audit, ch_dep, csv_safe, current_user, iso, require_admin

router = APIRouter(prefix="/api/wan", tags=["wan"])
RANGES = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24), "7d": timedelta(days=7),
          "30d": timedelta(days=30), "90d": timedelta(days=90), "365d": timedelta(days=365)}
RANGE = r"^(1h|6h|24h|7d|30d|90d|365d)$"


def window(range_: str | None, start: datetime | None, end: datetime | None, max_days: int = 31) -> tuple[datetime, datetime]:
    t1 = end or datetime.now(timezone.utc)
    t0 = start or t1 - RANGES.get(range_ or "24h", RANGES["24h"])
    t0 = t0 if t0.tzinfo else t0.replace(tzinfo=timezone.utc)
    t1 = t1 if t1.tzinfo else t1.replace(tzinfo=timezone.utc)
    if t0 >= t1:
        raise HTTPException(422, "start must be before end")
    if t1 - t0 > timedelta(days=max_days, hours=1):
        raise HTTPException(422, f"this view is limited to {max_days} days")
    return t0, t1


def _page(rows: list, page: int, size: int) -> dict:
    return {"items": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "size": size}


def _sort(rows: list[dict], key: str | None, desc: bool) -> list[dict]:
    if not key:
        return rows
    present = [r for r in rows if r.get(key) is not None]
    missing = [r for r in rows if r.get(key) is None]  # unknown values always last, never ranked as zero
    present.sort(key=lambda r: (r[key].lower() if isinstance(r[key], str) else r[key]), reverse=desc)
    return present + missing


async def _load(s: AsyncSession):
    ctx = await wan.Ctx.load(s)
    cfg = await wan.settings(s)
    targets = list((await s.execute(select(IcmpTarget).order_by(IcmpTarget.name))).scalars())
    return ctx, cfg, targets


# ------------------------------------------------------------------ meta
@router.get("/meta")
async def meta(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    cfg = await wan.settings(s)
    ctx = await wan.Ctx.load(s)
    targets = (await s.execute(select(IcmpTarget))).scalars().all()
    return {"statuses": [{"key": k, "label": wan.STATUS_LABEL[k]} for k in wan.STATUSES], "root_causes": cfg["root_cause_categories"],
            "ranges": list(RANGES), "is_admin": user.role == "admin", "timezone": getattr(user, "timezone", "") or "UTC",
            "isps": sorted({ctx.isp(t) for t in targets} | {x.isp_name for x in ctx.links.values() if x.isp_name}),
            "sites": sorted({ctx.site(t) for t in targets} | {ctx.link_site(x) for x in ctx.links.values() if ctx.link_site(x)}),
            "firewalls": [{"id": f.id, "name": f.name} for f in sorted(ctx.fws.values(), key=lambda f: f.name)],
            "classifications": wan.CLASS_LABEL}


# ------------------------------------------------------------------ overview
@router.get("/overview")
async def overview(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                   site: str | None = None, isp: str | None = None, tz: str = Query("UTC", max_length=64),
                   _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = window(range, start, end)
    ctx, cfg, targets = await _load(s)
    m = await WM.target_metrics(s, ch, targets, t0, t1, ctx, cfg)
    circ = await WM.circuits(s, ch, t0, t1, targets=targets, ctx=ctx, cfg=cfg, metrics=m)
    if site:
        circ = [c for c in circ if c["site"] == site]
    if isp:
        circ = [c for c in circ if c["isp"] == isp]
    inc = await WM.incident_analytics(s, t0, t1, tz=tz, site=site, isp=isp)
    col = wan.collector_status(await s.get(wan.WanCollector, 1), datetime.now(timezone.utc), int(cfg["stale_after_seconds"]))
    states = [c["state"] for c in circ]
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "collector": col,
            "totals": {"circuits": len(circ), "up": states.count("up"), "degraded": states.count("degraded"), "down": states.count("down"),
                       "unknown": states.count("unknown"), "paused": states.count("paused"),
                       "downtime_s": sum(c["downtime_s"] for c in circ), "outages": sum(c["outages"] for c in circ), **inc["totals"]},
            "summary": WM.group_rows(circ, "isp_site"), "by_location": inc["by_location"], "daily": inc["daily"]}


@router.get("/summary")
async def summary(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                  group: str = Query("isp_site", pattern=r"^(isp_site|isp|site|circuit|firewall)$"), q: str | None = Query(None, max_length=128),
                  site: str | None = None, isp: str | None = None, state: list[str] = Query(default=[]),
                  sort: str | None = Query(None, max_length=32), desc: bool = True, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = window(range, start, end)
    ctx, cfg, targets = await _load(s)
    circ = await WM.circuits(s, ch, t0, t1, targets=targets, ctx=ctx, cfg=cfg)
    if site:
        circ = [c for c in circ if c["site"] == site]
    if isp:
        circ = [c for c in circ if c["isp"] == isp]
    if state:
        circ = [c for c in circ if c["state"] in state]
    if q:
        ql = q.lower()
        circ = [c for c in circ if any(ql in str(c.get(k) or "").lower() for k in ("name", "isp", "site", "firewall", "circuit_id", "interface"))]
    rows = WM.group_rows(circ, group)
    return {"group": group, **_page(_sort(rows, sort or "downtime_s", desc), page, size)}


# ------------------------------------------------------------------ live monitoring
@router.get("/targets")
async def targets(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                  q: str | None = Query(None, max_length=128), state: list[str] = Query(default=[]), isp: str | None = None,
                  site: str | None = None, firewall_id: int | None = None, max_availability: float | None = Query(None, ge=0, le=100),
                  sort: str | None = Query(None, max_length=32), desc: bool = False, page: int = Query(1, ge=1),
                  size: int = Query(100, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                  ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = window(range, start, end)
    ctx, cfg, tgs = await _load(s)
    m = await WM.target_metrics(s, ch, tgs, t0, t1, ctx, cfg)
    rows = [WM.target_row(t, m[t.id], ctx) for t in tgs]
    totals = {"targets": len(rows), **{k: sum(1 for r in rows if r["state"] == k) for k in ("up", "degraded", "down", "unknown", "paused")},
              "outages": sum(r["outages"] for r in rows), "downtime_s": sum(r["downtime_s"] for r in rows),
              "checks": sum(r["checks"] for r in rows), "local_errors": sum(r["local_errors"] for r in rows)}
    if q:
        ql = q.lower()
        rows = [r for r in rows if any(ql in str(r.get(k) or "").lower() for k in ("name", "address", "isp", "site", "firewall", "circuit", "circuit_id"))]
    if state:
        rows = [r for r in rows if r["state"] in state]
    if isp:
        rows = [r for r in rows if r["isp"] == isp]
    if site:
        rows = [r for r in rows if r["site"] == site]
    if firewall_id:
        rows = [r for r in rows if r["firewall_id"] == firewall_id]
    if max_availability is not None:
        rows = [r for r in rows if r["availability"] is not None and r["availability"] <= max_availability]
    if not sort:
        order = {"down": 0, "degraded": 1, "unknown": 2, "up": 3, "paused": 4}
        rows.sort(key=lambda r: (order.get(r["state"], 5), r["name"].lower()))
    else:
        rows = _sort(rows, sort, desc)
    col = wan.collector_status(await s.get(wan.WanCollector, 1), datetime.now(timezone.utc), int(cfg["stale_after_seconds"]))
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "totals": totals, "collector": col, **_page(rows, page, size)}


async def _target(s: AsyncSession, tid: int) -> IcmpTarget:
    t = await s.get(IcmpTarget, tid)
    if not t:
        raise HTTPException(404, "target not found")
    return t


def _bucket(t0: datetime, t1: datetime) -> int:
    span = (t1 - t0).total_seconds()
    return next((x for x in (30, 60, 300, 900, 1800, 3600, 10800) if span / x <= 500), 21600)


@router.get("/targets/{tid}/history")
async def target_history(tid: int, range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                         _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = window(range, start, end)
    t = await _target(s, tid)
    ctx = await wan.Ctx.load(s)
    cfg = await wan.settings(s)
    m = await WM.target_metrics(s, ch, [t], t0, t1, ctx, cfg)
    b = max(_bucket(t0, t1), t.interval_seconds)
    outs = (await s.execute(select(WanOutage).where(WanOutage.target_id == t.id, WanOutage.started_at < t1,
                                                    or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > t0))
                            .order_by(WanOutage.started_at.desc()).limit(500))).scalars().all()
    evs = (await s.execute(select(IcmpEvent).where(IcmpEvent.target_id == t.id, IcmpEvent.at >= t0, IcmpEvent.at < t1)
                           .order_by(IcmpEvent.at.desc()).limit(500))).scalars().all()
    sd = []
    if t.isp_link_id:
        sd = (await s.execute(select(WanOutage).where(WanOutage.source == "sdwan", WanOutage.isp_link_id == t.isp_link_id, WanOutage.started_at < t1,
                                                      or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > t0)))).scalars().all()
    maint = [x for x in await WM._maintenance(s, t0, t1)
             if wan.maintenance_matches(x, site=ctx.site(t), isp=ctx.isp(t), link_id=t.isp_link_id, target_id=t.id)]
    return {"target": WM.target_row(t, m[t.id], ctx), "bucket_seconds": b,
            "points": await WM.timeseries(ch, t.id, t0, t1, b, t.interval_seconds * int(cfg["gap_factor"])),
            "timeline": await WM.state_timeline(s, t, t0, t1), "outages": [WM.outage_out(o) for o in outs],
            "sdwan_outages": [WM.outage_out(o) for o in sd],
            "maintenance": [{"id": x.id, "name": x.name, "start": iso(x.starts_at), "end": iso(x.ends_at)} for x in maint],
            "events": [{"at": iso(e.at), "from": e.from_state, "to": e.to_state, "previous_duration_s": e.previous_duration_s, "detail": e.detail}
                       for e in evs]}


@router.get("/targets/{tid}/observations")
async def observations(tid: int, start: datetime, end: datetime, limit: int = Query(500, ge=1, le=5000), _: User = Depends(current_user),
                       s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Raw checks behind a chart point or outage interval."""
    t0, t1 = window(None, start, end)
    await _target(s, tid)
    rows = await ch.aquery(
        "SELECT ts, sent, received, rtts, rtt_avg, jitter, up, state, error_class, error, attempts, sched_delay_ms, ingested_at "
        "FROM icmp_results WHERE target_id = {id:UInt32} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} ORDER BY ts LIMIT {n:UInt32}",
        {"id": tid, "t0": t0, "t1": t1, "n": limit})
    for r in rows:
        for k in ("ts", "ingested_at"):
            r[k] = wan.aware(r[k]).isoformat() if r.get(k) else None
        r["rtts"] = [round(float(x), 2) for x in r.get("rtts") or []]
        for k in ("rtt_avg", "jitter", "sched_delay_ms"):
            r[k] = WM._f(r.get(k))
    return {"items": rows, "truncated": len(rows) >= limit}


class PauseIn(BaseModel):
    reason: str = Field("", max_length=255)


@router.post("/targets/{tid}/pause")
async def pause(tid: int, body: PauseIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await _target(s, tid)
    await icmp.set_paused(s, t, True, body.reason or f"paused by {user.username}")
    await s.commit()
    await audit(s, request, user.username, "wan_target_pause", t.address, {"reason": body.reason})
    return {"ok": True, "state": t.state}


@router.post("/targets/{tid}/resume")
async def resume(tid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await _target(s, tid)
    await icmp.set_paused(s, t, False, "")
    await s.commit()
    await audit(s, request, user.username, "wan_target_resume", t.address)
    return {"ok": True, "state": t.state}


@router.post("/targets/{tid}/test")
async def test_target(tid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """One-off connectivity test with the target's settings; does not change state, history or outages."""
    t = await _target(s, tid)
    r = await icmp.probe(t)
    await audit(s, request, user.username, "wan_target_test", t.address)
    return {"sent": r.sent, "received": r.received, "rtts": r.rtts, "loss_pct": r.loss_pct, "rtt_avg": r.rtt_avg, "jitter": r.jitter,
            "error": r.error, "error_class": r.error_class, "attempts": r.attempts}


# ------------------------------------------------------------------ circuit inventory
class CircuitIn(BaseModel):
    name: str = Field("", max_length=128)
    circuit_id: str = Field("", max_length=128)
    isp_name: str = Field(min_length=1, max_length=128)
    site: str = Field("", max_length=128)
    location: str = Field("", max_length=255)
    firewall_id: int | None = None
    interface: str = Field("", max_length=64)
    gateway: str = Field("", max_length=64)
    bandwidth_mbps: float | None = Field(None, ge=0, le=1_000_000)
    role: str = Field("primary", pattern=r"^(primary|backup)$")
    target_availability: float = Field(99.5, ge=0, le=100)
    owner: str = Field("", max_length=128)
    support_contact: str = Field("", max_length=255)
    notes: str = Field("", max_length=4000)
    enabled: bool = True
    monitoring_start: datetime | None = None


@router.get("/circuits")
async def circuit_list(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    ctx = await wan.Ctx.load(s)
    targets = (await s.execute(select(IcmpTarget))).scalars().all()
    rows = [WM.circuit_inventory_row(lk, ctx, list(targets)) for lk in ctx.links.values() if not lk.hidden or any(t.isp_link_id == lk.id for t in targets)]
    rows.sort(key=lambda r: ((r["isp_name"] or r["as_org"] or "~").lower(), r["effective_site"].lower(), r["label"].lower()))
    return {"items": rows, "unlinked_targets": [{"id": t.id, "name": t.name, "address": t.address} for t in targets if not t.isp_link_id]}


async def _circuit_body(s: AsyncSession, body: CircuitIn, current: IspLink | None = None) -> dict:
    d = body.model_dump()
    d = {k: v.strip() if isinstance(v, str) else v for k, v in d.items()}
    if d["firewall_id"] is not None and not await s.get(Firewall, d["firewall_id"]):
        raise HTTPException(422, "unknown firewall")
    if d["firewall_id"] is None:
        d["interface"] = d["interface"] or ""
    if d["gateway"]:
        try:
            d["gateway"] = icmp.validate_address(d["gateway"])
        except ValueError as e:
            raise HTTPException(422, f"gateway: {e}")
    dup = select(IspLink).where(IspLink.firewall_id == d["firewall_id"], IspLink.interface == d["interface"])
    if d["firewall_id"] is not None and d["interface"]:
        other = (await s.execute(dup)).scalars().first()
        if other and (current is None or other.id != current.id):
            raise HTTPException(409, "that firewall interface already belongs to another circuit")
    return d


@router.post("/circuits", status_code=201)
async def circuit_create(body: CircuitIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    d = await _circuit_body(s, body)
    lk = IspLink(**d)
    s.add(lk)
    await s.commit()
    await audit(s, request, user.username, "wan_circuit_create", lk.name or lk.circuit_id or str(lk.id), {"isp": lk.isp_name, "site": lk.site})
    return {"id": lk.id}


@router.put("/circuits/{cid}")
async def circuit_update(cid: int, body: CircuitIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    lk = await s.get(IspLink, cid)
    if not lk:
        raise HTTPException(404, "circuit not found")
    d = await _circuit_body(s, body, lk)
    if lk.firewall_id is not None and lk.interface and (d["firewall_id"], d["interface"]) != (lk.firewall_id, lk.interface):
        raise HTTPException(422, "the firewall and interface of a discovered SD-WAN link cannot change; create a new circuit instead")
    for k, v in d.items():
        setattr(lk, k, v)
    await s.commit()
    await audit(s, request, user.username, "wan_circuit_update", str(cid), {"isp": lk.isp_name, "site": lk.site})
    return {"ok": True}


@router.delete("/circuits/{cid}")
async def circuit_delete(cid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    lk = await s.get(IspLink, cid)
    if not lk:
        raise HTTPException(404, "circuit not found")
    if lk.firewall_id is not None:
        raise HTTPException(409, "SD-WAN links discovered from a firewall are hidden, not deleted (they come back with the next logs)")
    n = (await s.execute(select(func.count()).select_from(IcmpTarget).where(IcmpTarget.isp_link_id == cid))).scalar_one()
    if n:
        raise HTTPException(409, f"{n} monitored target(s) belong to this circuit; move or delete them first")
    await s.delete(lk)
    await s.commit()
    await audit(s, request, user.username, "wan_circuit_delete", str(cid))
    return {"ok": True}


# ------------------------------------------------------------------ outages
def _outage_query(t0, t1, site, isp, circuit_id, target_id, kind, ongoing, source):
    q = select(WanOutage).where(WanOutage.started_at < t1, or_(WanOutage.recovered_at.is_(None), WanOutage.recovered_at > t0))
    for col, v in ((WanOutage.site, site), (WanOutage.isp_name, isp), (WanOutage.isp_link_id, circuit_id), (WanOutage.target_id, target_id),
                   (WanOutage.kind, kind), (WanOutage.source, source)):
        if v is not None and v != "":
            q = q.where(col == v)
    if ongoing is not None:
        q = q.where(WanOutage.recovered_at.is_(None) if ongoing else WanOutage.recovered_at.is_not(None))
    return q


@router.get("/outages")
async def outages(range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                  site: str | None = None, isp: str | None = None, circuit_id: int | None = None, target_id: int | None = None,
                  kind: str | None = Query("down", pattern=r"^(down|degraded)$"), ongoing: bool | None = None,
                  source: str | None = Query(None, pattern=r"^(icmp|sdwan)$"), page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500),
                  _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    t0, t1 = window(range, start, end, 366)
    q = _outage_query(t0, t1, site, isp, circuit_id, target_id, kind, ongoing, source)
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await s.execute(q.order_by(WanOutage.started_at.desc()).offset((page - 1) * size).limit(size))).scalars().all()
    return {"items": [WM.outage_out(o) for o in rows], "total": total, "page": page, "size": size}


@router.get("/outages.csv")
async def outages_csv(request: Request, range: str | None = Query("30d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                      site: str | None = None, isp: str | None = None, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    t0, t1 = window(range, start, end, 366)
    rows = (await s.execute(_outage_query(t0, t1, site, isp, None, None, "down", None, None).order_by(WanOutage.started_at).limit(50000))).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["outage_id", "source", "isp", "site", "circuit", "target", "address", "last_ok_utc", "started_utc", "detected_utc", "recovered_utc",
                "duration_minutes", "ongoing", "incident_id", "maintenance"])
    for o in rows:
        w.writerow([o.id, o.source, csv_safe(o.isp_name), csv_safe(o.site), csv_safe(o.circuit_name), csv_safe(o.target_name), o.address,
                    iso(o.last_ok_at) or "", iso(o.started_at), iso(o.detected_at), iso(o.recovered_at) or "",
                    round(o.duration_s / 60, 1) if o.duration_s is not None else "", "yes" if o.recovered_at is None else "no", o.incident_id or "",
                    "yes" if o.maintenance_id else "no"])
    await audit(s, request, user.username, "wan_outage_export", f"{t0.isoformat()}..{t1.isoformat()}")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="wan-outages.csv"'})


# ------------------------------------------------------------------ ISP incidents
def inc_out(i: Incident, outs: list[WanOutage] | None = None) -> dict:
    from ..incidents import sla_state
    d = {"id": i.id, "title": i.title, "status": i.status, "status_label": wan.STATUS_LABEL.get(i.status, i.status), "severity": i.severity,
         "entity_type": i.entity_type, "entity": i.entity, "site": i.site, "isp": i.isp_name, "isp_link_id": i.isp_link_id,
         "correlation_key": i.correlation_key, "assignee": i.assignee, "summary": i.summary, "probable_cause": i.probable_cause,
         "root_cause_category": i.root_cause_category, "root_cause_detail": i.root_cause_detail, "first_seen": iso(i.first_seen),
         "last_seen": iso(i.last_seen), "created_at": iso(i.created_at), "acknowledged_at": iso(i.acknowledged_at), "resolved_at": iso(i.resolved_at),
         "resolve_s": round((wan.aware(i.resolved_at) - wan.aware(i.first_seen)).total_seconds()) if i.resolved_at else None,
         "linked": i.linked or [], "tasks": i.tasks or [], "sla": sla_state(i)}
    if outs is not None:
        d["outages"] = [WM.outage_out(o) for o in outs]
        d["outage_count"] = len(outs)
        d["ongoing"] = any(o.recovered_at is None for o in outs)
        d["downtime_s"] = sum((o.duration_s or 0) for o in outs if o.recovered_at is not None)
    return d


@router.get("/incidents")
async def incidents(range: str | None = Query("30d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                    status: list[str] = Query(default=[]), site: str | None = None, isp: str | None = None, circuit_id: int | None = None,
                    root_cause: str | None = Query(None, max_length=48), missing_root_cause: bool = False, open_only: bool = False,
                    day: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"), tz: str = Query("UTC", max_length=64),
                    q: str | None = Query(None, max_length=128), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                    _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    t0, t1 = window(range, start, end, 366)
    if day:  # one calendar day in the viewer's time zone (chart click-through)
        z = WM.tzinfo(tz)
        d0 = datetime.fromisoformat(day).replace(tzinfo=z)
        t0, t1 = d0.astimezone(timezone.utc), (d0 + timedelta(days=1)).astimezone(timezone.utc)
    qy = select(Incident).where(Incident.category == "wan")
    qy = qy.where(Incident.status.in_(wan.WAN_OPEN)) if open_only else qy.where(Incident.first_seen >= t0, Incident.first_seen < t1)
    if status:
        qy = qy.where(Incident.status.in_(status))
    if site:
        qy = qy.where(Incident.site == site)
    if isp:
        qy = qy.where(Incident.isp_name == isp)
    if circuit_id:
        qy = qy.where(Incident.isp_link_id == circuit_id)
    if root_cause:
        qy = qy.where(Incident.root_cause_category == root_cause)
    if missing_root_cause:
        qy = qy.where(Incident.root_cause_category.is_(None))
    if q:
        qy = qy.where(Incident.title.ilike(f"%{q}%") | Incident.entity.ilike(f"%{q}%") | Incident.summary.ilike(f"%{q}%"))
    total = (await s.execute(select(func.count()).select_from(qy.subquery()))).scalar_one()
    rows = (await s.execute(qy.order_by(Incident.status.in_(wan.WAN_OPEN).desc(), Incident.first_seen.desc())
                            .offset((page - 1) * size).limit(size))).scalars().all()
    ids = [i.id for i in rows]
    outs = (await s.execute(select(WanOutage).where(WanOutage.incident_id.in_(ids)))).scalars().all() if ids else []
    by: dict[int, list] = {}
    for o in outs:
        by.setdefault(o.incident_id, []).append(o)
    items = []
    for i in rows:
        d = inc_out(i, by.get(i.id, []))
        d.pop("outages")
        items.append(d)
    return {"items": items, "total": total, "page": page, "size": size, "window": {"start": t0.isoformat(), "end": t1.isoformat()}}


async def _incident(s: AsyncSession, iid: int) -> Incident:
    i = await s.get(Incident, iid)
    if not i or i.category != "wan":
        raise HTTPException(404, "ISP incident not found")
    return i


@router.get("/incidents/{iid}")
async def incident(iid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await _incident(s, iid)
    outs = (await s.execute(select(WanOutage).where(WanOutage.incident_id == iid).order_by(WanOutage.started_at))).scalars().all()
    comments = (await s.execute(select(IncidentComment).where(IncidentComment.incident_id == iid).order_by(IncidentComment.ts))).scalars().all()
    timeline = sorted([{"ts": iso(o.started_at), "kind": "outage", "title": f"{o.target_name} first failed check ({o.source})", "ref": o.id}
                       for o in outs] +
                      [{"ts": iso(o.detected_at), "kind": "detected", "title": f"{o.target_name} confirmed down after {o.failed_checks} failed checks",
                        "ref": o.id} for o in outs] +
                      [{"ts": iso(o.recovered_at), "kind": "recovered", "title": f"{o.target_name} answered again ({wan.fmt_dur(o.duration_s)})", "ref": o.id}
                       for o in outs if o.recovered_at] +
                      [{"ts": iso(c.ts), "kind": c.kind, "title": c.body, "author": c.author, "ref": c.id} for c in comments],
                      key=lambda x: x["ts"] or "")
    related = []
    if outs:
        a = min(wan.aware(o.started_at) for o in outs)
        b = max((wan.aware(o.recovered_at) or datetime.now(timezone.utc)) for o in outs)
        for r in (await s.execute(select(Incident).where(Incident.category == "wan", Incident.id != iid, Incident.first_seen < b,
                                                         Incident.last_seen > a).limit(20))).scalars():
            related.append({"id": r.id, "title": r.title, "status": r.status, "site": r.site, "isp": r.isp_name})
    inv = None
    if outs:
        try:
            o0 = outs[0]
            inv = await wan.investigate(s, at=wan.aware(o0.detected_at), target_id=o0.target_id, link_id=o0.isp_link_id, site=o0.site)
        except Exception:
            inv = None
    return {**inc_out(i, outs), "timeline": timeline, "concurrent": related, "investigation": inv,
            "comments": [{"id": c.id, "ts": iso(c.ts), "author": c.author, "kind": c.kind, "body": c.body} for c in comments]}


class WanIncidentPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(open|in_progress|monitoring|resolved|closed)$")
    assignee: str | None = Field(None, max_length=64)
    severity: str | None = Field(None, pattern=r"^(low|medium|high|critical)$")
    root_cause_category: str | None = Field(None, max_length=48)
    root_cause_detail: str | None = Field(None, max_length=10_000)
    summary: str | None = Field(None, max_length=10_000)
    linked: list[int] | None = Field(None, max_length=50)


@router.patch("/incidents/{iid}")
async def incident_update(iid: int, body: WanIncidentPatch, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await _incident(s, iid)
    data = body.model_dump(exclude_unset=True)
    cfg = await wan.settings(s)
    now = datetime.now(timezone.utc)
    if "root_cause_category" in data:
        rc = data["root_cause_category"] or None
        if rc and rc not in {c["key"] for c in cfg["root_cause_categories"]}:
            raise HTTPException(422, "unknown root-cause category")
        if rc != i.root_cause_category:
            s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status",
                                  body=f"Root cause set to {next((c['label'] for c in cfg['root_cause_categories'] if c['key'] == rc), rc) if rc else '(cleared)'}"))
            i.root_cause_category = rc
    if "root_cause_detail" in data:
        i.root_cause_detail = data["root_cause_detail"] or ""
    if data.get("status") and data["status"] != i.status:
        new = data["status"]
        if new == "closed" and not (i.root_cause_category or data.get("root_cause_category")):
            raise HTTPException(422, "record a root-cause category before closing (use 'Unknown / under investigation' if it stays unknown)")
        if new in ("resolved", "closed"):
            open_outs = (await s.execute(select(WanOutage.id).where(WanOutage.incident_id == i.id, WanOutage.recovered_at.is_(None)))).first()
            if open_outs and new == "closed":
                raise HTTPException(422, "an outage of this incident is still in progress")
            i.resolved_at = i.resolved_at or now
            i.acknowledged_at = i.acknowledged_at or now
        else:
            i.resolved_at = None if new in wan.WAN_OPEN else i.resolved_at
            if new == "in_progress" and not i.acknowledged_at:
                i.acknowledged_at = now
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status",
                              body=f"Status {wan.STATUS_LABEL.get(i.status, i.status)} → {wan.STATUS_LABEL[new]}"))
        i.status = new
    if "assignee" in data and data["assignee"] != i.assignee:
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status", body=f"Owner set to {data['assignee'] or 'nobody'}"))
        i.assignee = data["assignee"] or None
        if i.assignee and i.status == "open":
            i.status, i.acknowledged_at = "in_progress", i.acknowledged_at or now
    if data.get("severity") and data["severity"] != i.severity:
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status", body=f"Severity {i.severity} → {data['severity']}"))
        i.severity = data["severity"]
    if "summary" in data:
        i.summary = data["summary"] or ""
    if "linked" in data:
        ok = {x for (x,) in (await s.execute(select(Incident.id).where(Incident.id.in_(data["linked"] or []), Incident.id != i.id))).all()}
        i.linked = sorted(ok)
    await s.commit()
    await audit(s, request, user.username, "wan_incident_update", str(iid), data)
    outs = (await s.execute(select(WanOutage).where(WanOutage.incident_id == iid))).scalars().all()
    return inc_out(i, outs)


@router.post("/incidents/{iid}/acknowledge")
async def incident_ack(iid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    i = await _incident(s, iid)
    if not i.acknowledged_at:
        i.acknowledged_at = datetime.now(timezone.utc)
        i.assignee = i.assignee or user.username
        if i.status == "open":
            i.status = "in_progress"
        s.add(IncidentComment(incident_id=i.id, author=user.username, kind="status", body="Acknowledged"))
        await s.commit()
        await audit(s, request, user.username, "wan_incident_ack", str(iid))
    return {"ok": True, "status": i.status, "acknowledged_at": iso(i.acknowledged_at)}


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


@router.post("/incidents/{iid}/comments", status_code=201)
async def incident_comment(iid: int, body: CommentIn, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _incident(s, iid)
    c = IncidentComment(incident_id=iid, author=user.username, kind="comment", body=body.body)
    s.add(c)
    await s.commit()
    return {"id": c.id, "ts": iso(c.ts), "author": c.author, "kind": c.kind, "body": c.body}


# ------------------------------------------------------------------ analytics / investigation / events
@router.get("/analytics")
async def analytics(range: str | None = Query("30d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                    tz: str = Query("UTC", max_length=64), site: str | None = None, isp: str | None = None,
                    _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = window(range, start, end, 366)
    out = await WM.incident_analytics(s, t0, t1, tz=tz, site=site, isp=isp)
    # downtime by ISP / site / circuit from the outage records (availability needs observations: 31 days max)
    if t1 - t0 <= timedelta(days=31, hours=1):
        ctx, cfg, targets = await _load(s)
        circ = await WM.circuits(s, ch, t0, t1, targets=targets, ctx=ctx, cfg=cfg)
        if site:
            circ = [c for c in circ if c["site"] == site]
        if isp:
            circ = [c for c in circ if c["isp"] == isp]
        out["by_isp"] = sorted(WM.group_rows(circ, "isp"), key=lambda r: -r["downtime_s"])
        out["by_site"] = sorted(WM.group_rows(circ, "site"), key=lambda r: -r["downtime_s"])
        out["by_circuit"] = sorted(WM.group_rows(circ, "circuit"), key=lambda r: -r["downtime_s"])[:50]
        z = WM.tzinfo(tz)
        days = out["daily"]["days"]
        avail = []
        for d in days:
            d0 = datetime.fromisoformat(d).replace(tzinfo=z).astimezone(timezone.utc)
            a, b = max(d0, t0), min(d0 + timedelta(days=1), t1)
            obs = sum(WM._secs(WM.clip(c["_observed"], a, b)) for c in circ)
            dn = sum(WM._secs(WM.clip(c["_down"], a, b)) for c in circ)
            avail.append({"day": d, "availability": round(100 * (obs - dn) / obs, 4) if obs > 0 else None, "downtime_s": round(dn)})
        out["availability_daily"] = avail
    else:
        out["by_isp"] = out["by_site"] = out["by_circuit"] = out["availability_daily"] = None
        out["note"] = "Per-circuit availability is computed for ranges up to 31 days; incident counts cover the whole range."
    return out


@router.get("/investigate")
async def investigate(target_id: int | None = None, circuit_id: int | None = None, site: str | None = Query(None, max_length=128),
                      at: datetime | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    if not (target_id or circuit_id or site):
        raise HTTPException(422, "choose a target, a circuit or a site")
    return await wan.investigate(s, at=at if at is None or at.tzinfo else at.replace(tzinfo=timezone.utc),
                                 target_id=target_id, link_id=circuit_id, site=site)


@router.get("/events")
async def events(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                 target_id: int | None = None, to_state: str | None = Query(None, pattern=r"^(up|down|degraded|unknown|paused)$"),
                 page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    t0, t1 = window(range, start, end, 366)
    q = select(IcmpEvent).where(IcmpEvent.at >= t0, IcmpEvent.at < t1)
    if target_id:
        q = q.where(IcmpEvent.target_id == target_id)
    if to_state:
        q = q.where(IcmpEvent.to_state == to_state)
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await s.execute(q.order_by(IcmpEvent.at.desc()).offset((page - 1) * size).limit(size))).scalars().all()
    ctx = await wan.Ctx.load(s)
    names = {t.id: t for t in (await s.execute(select(IcmpTarget))).scalars()}
    return {"total": total, "page": page, "size": size, "items": [
        {"id": e.id, "at": iso(e.at), "target_id": e.target_id, "target": names[e.target_id].name if e.target_id in names else f"#{e.target_id}",
         "address": names[e.target_id].address if e.target_id in names else "", "isp": ctx.isp(names[e.target_id]) if e.target_id in names else "",
         "site": ctx.site(names[e.target_id]) if e.target_id in names else "", "from": e.from_state, "to": e.to_state,
         "previous_duration_s": e.previous_duration_s, "detail": e.detail} for e in rows]}


@router.get("/collector")
async def collector(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    cfg = await wan.settings(s)
    return wan.collector_status(await s.get(wan.WanCollector, 1), datetime.now(timezone.utc), int(cfg["stale_after_seconds"]))


# ------------------------------------------------------------------ maintenance / settings
class MaintenanceIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scope: str = Field("all", pattern=r"^(all|site|isp|circuit|target)$")
    scope_value: str = Field("", max_length=255)
    starts_at: datetime
    ends_at: datetime
    reason: str = Field("", max_length=4000)


@router.get("/maintenance")
async def maintenance_list(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(WanMaintenance).order_by(WanMaintenance.starts_at.desc()).limit(500))).scalars().all()
    now = datetime.now(timezone.utc)
    return {"items": [{"id": m.id, "name": m.name, "scope": m.scope, "scope_value": m.scope_value, "starts_at": iso(m.starts_at),
                       "ends_at": iso(m.ends_at), "reason": m.reason, "created_by": m.created_by,
                       "active": wan.aware(m.starts_at) <= now < wan.aware(m.ends_at)} for m in rows]}


@router.post("/maintenance", status_code=201)
async def maintenance_create(body: MaintenanceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    a = body.starts_at if body.starts_at.tzinfo else body.starts_at.replace(tzinfo=timezone.utc)
    b = body.ends_at if body.ends_at.tzinfo else body.ends_at.replace(tzinfo=timezone.utc)
    if b <= a or b - a > timedelta(days=31):
        raise HTTPException(422, "a maintenance window must end after it starts and last at most 31 days")
    if body.scope != "all" and not body.scope_value.strip():
        raise HTTPException(422, "choose what the maintenance applies to")
    m = WanMaintenance(name=body.name.strip(), scope=body.scope, scope_value=body.scope_value.strip(), starts_at=a, ends_at=b,
                       reason=body.reason, created_by=user.username)
    s.add(m)
    await s.commit()
    await audit(s, request, user.username, "wan_maintenance_create", m.name, {"scope": m.scope, "value": m.scope_value})
    return {"id": m.id}


@router.delete("/maintenance/{mid}")
async def maintenance_delete(mid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    m = await s.get(WanMaintenance, mid)
    if not m:
        raise HTTPException(404, "not found")
    await s.delete(m)
    await s.commit()
    await audit(s, request, user.username, "wan_maintenance_delete", m.name)
    return {"ok": True}


@router.get("/settings")
async def settings_get(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await wan.settings(s)


@router.put("/settings")
async def settings_put(body: dict, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        out = await wan.save_settings(s, body, user.username)
    except (ValueError, TypeError) as e:
        raise HTTPException(422, str(e))
    await audit(s, request, user.username, "wan_settings_update", "", {k: body[k] for k in body if k != "root_cause_categories"})
    return out
