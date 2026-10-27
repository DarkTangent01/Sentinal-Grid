"""APIs: ISP / WAN link availability, outages, quality and provider scorecards."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import icmp, isp
from ..analytics.filters import EventFilter
from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import Firewall, IcmpTarget, IspLink, User
from ..db.pg import get_session
from .deps import audit, ch_dep, csv_safe, current_user, require_admin

router = APIRouter(prefix="/api/isp", tags=["isp"])
RANGE = r"^(1h|24h|7d|30d)$"


def _window(range_: str | None, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    try:
        t0, t1 = EventFilter(range=range_ or "7d", start=start, end=end).window()
    except ValueError as e:
        raise HTTPException(422, str(e))
    if t1 - t0 > timedelta(days=max(31, get_settings().max_query_range_days)):
        raise HTTPException(422, "time range is limited to 31 days")
    return t0, t1


def _bucket(t0: datetime, t1: datetime) -> int:
    span = (t1 - t0).total_seconds()
    for b in (60, 300, 900, 1800, 3600, 10800, 21600):
        if span / b <= 400:
            return b
    return 86400


@router.get("/overview")
async def overview(range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                   firewall_id: list[int] = Query(default=[]), min_outage_seconds: int = Query(60, ge=0, le=3600),
                   include_hidden: bool = False, _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                   ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await isp.report(ch, s, t0, t1, firewall_id or None, min_outage_seconds, include_hidden)


@router.get("/links/{fw_id}/{interface}")
async def link(fw_id: int, interface: str, range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None,
               end: datetime | None = None, min_outage_seconds: int = Query(60, ge=0, le=3600), _: User = Depends(current_user),
               s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    r = await isp.link_detail(ch, s, fw_id, interface, t0, t1, min_outage_seconds, _bucket(t0, t1))
    if not r["found"]:
        raise HTTPException(404, "no SD-WAN data for this link in the selected range")
    return r


@router.get("/outages.csv")
async def outages_csv(request: Request, range: str | None = Query("30d", pattern=RANGE), start: datetime | None = None,
                      end: datetime | None = None, firewall_id: list[int] = Query(default=[]),
                      min_outage_seconds: int = Query(60, ge=0, le=3600), user: User = Depends(current_user),
                      s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Outage log for provider escalations / credit claims."""
    t0, t1 = _window(range, start, end)
    rep = await isp.report(ch, s, t0, t1, firewall_id or None, min_outage_seconds)
    links = {l["key"]: l for l in rep["links"]}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["isp", "circuit_id", "firewall", "interface", "start_utc", "end_utc", "duration_minutes", "ongoing"])
    for o in rep["timeline"]:
        l = links.get(o["key"], {})
        w.writerow([csv_safe(o["isp_name"]), csv_safe(l.get("circuit_id", "")), o["firewall_name"], o["interface"], o["start"], o["end"],
                    round(o["duration_s"] / 60, 1), "yes" if l.get("status") == "down" and o["end"] >= rep["window"]["end"][:19] else "no"])
    await audit(s, request, user.username, "isp_outage_export", f"{t0.isoformat()}..{t1.isoformat()}")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="isp-outages.csv"'})


class LinkIn(BaseModel):
    isp_name: str = Field("", max_length=128)
    circuit_id: str = Field("", max_length=128)
    bandwidth_mbps: float | None = Field(None, ge=0, le=1_000_000)
    target_availability: float = Field(99.5, ge=0, le=100)
    outage_checks: list[str] = Field(default_factory=list, max_length=50)
    hidden: bool = False
    notes: str = Field("", max_length=4000)
    support_contact: str = Field("", max_length=255)


@router.put("/config/{link_id}")
async def update_link(link_id: int, body: LinkIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(IspLink, link_id)
    if not c:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump().items():
        setattr(c, k, v.strip() if isinstance(v, str) else v)
    await s.commit()
    await audit(s, request, user.username, "isp_link_update", f"{c.firewall_id}:{c.interface}", {"isp_name": c.isp_name})
    return {"ok": True}


@router.post("/discover")
async def run_discovery(request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Refresh interface aliases and SD-WAN gateways from the firewalls (read-only GET requests)."""
    res = await isp.discover(s)
    await audit(s, request, user.username, "isp_discover", "", res)
    return res


# ------------------------------------------------------------------ ICMP reachability (NMS-style)
class IcmpTargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=255)
    isp_link_id: int | None = None
    isp_name: str = Field("", max_length=128)
    site: str = Field("", max_length=128)
    enabled: bool = True
    interval_seconds: int = Field(30, ge=10, le=3600)
    probes: int = Field(3, ge=1, le=10)
    timeout_ms: int = Field(1000, ge=100, le=5000)
    down_after: int = Field(3, ge=1, le=20)
    up_after: int = Field(2, ge=1, le=20)
    rtt_warn_ms: float = Field(150.0, ge=1, le=10000)
    loss_warn_pct: float = Field(20.0, ge=1, le=100)


async def _icmp_body(s: AsyncSession, body: IcmpTargetIn) -> dict:
    try:
        addr = icmp.validate_address(body.address)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.isp_link_id and not await s.get(IspLink, body.isp_link_id):
        raise HTTPException(422, "unknown ISP link")
    return {**body.model_dump(), "address": addr}


@router.get("/icmp/overview")
async def icmp_overview(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                        _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await icmp.overview(s, ch, t0, t1)


@router.get("/icmp/targets/{tid}/timeseries")
async def icmp_timeseries(tid: int, range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None,
                          end: datetime | None = None, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    span = (t1 - t0).total_seconds()
    b = next((x for x in (30, 60, 300, 900, 1800, 3600, 10800) if span / x <= 500), 21600)
    return {"bucket_seconds": b, "points": await icmp.timeseries(ch, tid, t0, t1, b)}


@router.post("/icmp/targets", status_code=201)
async def icmp_create(body: IcmpTargetIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    data = await _icmp_body(s, body)
    if (await s.execute(select(IcmpTarget.id).where(IcmpTarget.address == data["address"]))).first():
        raise HTTPException(409, "this address is already monitored")
    t = IcmpTarget(**data, created_by=user.username)
    s.add(t)
    await s.commit()
    await audit(s, request, user.username, "icmp_target_create", t.address, {"name": t.name})
    return {"id": t.id}


@router.put("/icmp/targets/{tid}")
async def icmp_update(tid: int, body: IcmpTargetIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await s.get(IcmpTarget, tid)
    if not t:
        raise HTTPException(404, "not found")
    data = await _icmp_body(s, body)
    if data["address"] != t.address:  # a different host: start its history fresh
        t.state, t.state_since, t.fail_streak, t.ok_streak = "unknown", None, 0, 0
    for k, v in data.items():
        setattr(t, k, v)
    await s.commit()
    await audit(s, request, user.username, "icmp_target_update", t.address, {"name": t.name})
    return {"ok": True}


@router.delete("/icmp/targets/{tid}")
async def icmp_delete(tid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    t = await s.get(IcmpTarget, tid)
    if not t:
        raise HTTPException(404, "not found")
    await s.delete(t)
    await s.commit()
    await audit(s, request, user.username, "icmp_target_delete", t.address)
    return {"ok": True}


@router.post("/icmp/targets/{tid}/probe")
async def icmp_probe_now(tid: int, _: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """One-off ping (does not change state or history)."""
    t = await s.get(IcmpTarget, tid)
    if not t:
        raise HTTPException(404, "not found")
    r = await icmp.ping(t.address, t.probes, t.timeout_ms)
    return {"sent": r.sent, "received": r.received, "rtts": r.rtts, "loss_pct": r.loss_pct, "rtt_avg": r.rtt_avg, "error": r.error}


@router.get("/icmp/suggestions")
async def icmp_suggestions(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Addresses worth monitoring that are not yet targets: ISP link gateways learned from SD-WAN logs."""
    have = {a for (a,) in (await s.execute(select(IcmpTarget.address))).all()}
    fws = {f.id: f.name for f in (await s.execute(select(Firewall))).scalars()}
    out = []
    for lk in (await s.execute(select(IspLink).where(IspLink.hidden.is_(False)))).scalars():
        if lk.gateway and lk.gateway not in have:
            out.append({"address": lk.gateway, "name": f"{lk.isp_name or lk.alias or lk.interface} gateway ({fws.get(lk.firewall_id, '')})",
                        "isp_link_id": lk.id, "isp": lk.isp_name or lk.as_org or lk.alias or lk.interface})
    return out
