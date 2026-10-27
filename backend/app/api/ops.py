"""APIs: firewall health (resources, reboots, FortiAnalyzer, log feeds), site-to-site IPsec tunnels, BGP peers, non-FortiGate log sources."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import bgp, fwhealth, vpnmon
from ..analytics.filters import EventFilter
from ..db.ch import ClickHouse
from ..db.models import Firewall, LogSource, User
from ..db.pg import get_session
from ..ingest.generic import SOURCE_ID_BASE
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["ops"])
RANGE = r"^(1h|24h|7d|30d)$"


def _window(range_: str | None, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    try:
        t0, t1 = EventFilter(range=range_ or "24h", start=start, end=end).window()
    except ValueError as e:
        raise HTTPException(422, str(e))
    if t1 - t0 > timedelta(days=31):
        raise HTTPException(422, "time range is limited to 31 days")
    return t0, t1


def _bucket(t0: datetime, t1: datetime) -> int:
    span = (t1 - t0).total_seconds()
    return next((b for b in (300, 900, 1800, 3600, 10800, 21600) if span / b <= 300), 86400)


@router.get("/fwhealth/overview")
async def fw_overview(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                      firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                      ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await fwhealth.overview(ch, s, t0, t1, firewall_id or None)


@router.get("/fwhealth/{fw_id}/timeseries")
async def fw_timeseries(fw_id: int, range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                        _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    b = _bucket(t0, t1)
    return {"bucket_seconds": b, "points": await fwhealth.timeseries(ch, fw_id, t0, t1, b)}


@router.get("/vpn-tunnels/overview")
async def vpn_overview(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                       firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await vpnmon.overview(ch, t0, t1, firewall_id or None)


@router.get("/vpn-tunnels/{fw_id}/{tunnel}")
async def vpn_tunnel(fw_id: int, tunnel: str, range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None,
                     end: datetime | None = None, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    t = next((x for x in (await vpnmon.tunnels(ch, t0, t1, [fw_id]))["tunnels"] if x["tunnel"] == tunnel), None)
    if t is None:
        raise HTTPException(404, "no data for this tunnel in the selected range")
    return t


# ------------------------------------------------------------------ BGP
@router.get("/bgp/overview")
async def bgp_overview(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                       firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                       ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await bgp.report(ch, s, t0, t1, firewall_id or None)


@router.get("/bgp/peers/{fw_id}/{peer}")
async def bgp_peer(fw_id: int, peer: str, range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None,
                   end: datetime | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                   ch: ClickHouse = Depends(ch_dep)):
    try:
        peer = str(ipaddress.ip_address(peer))
    except ValueError:
        raise HTTPException(422, "peer must be an IP address")
    t0, t1 = _window(range, start, end)
    d = await bgp.peer_detail(ch, s, fw_id, peer, t0, t1)
    if d is None:
        raise HTTPException(404, "no BGP data for this peer in the selected range")
    return d


@router.get("/bgp/prefixes")
async def bgp_prefixes(range: str | None = Query("24h", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                       firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                       ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await bgp.prefixes_report(ch, s, t0, t1, firewall_id or None)


@router.get("/bgp/audit")
async def bgp_audit(firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await bgp.audit_report(s, firewall_id or None)


@router.get("/bgp/security")
async def bgp_security(range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                       firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                       ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await bgp.security_report(ch, s, t0, t1, firewall_id or None)


@router.get("/bgp/correlation")
async def bgp_correlation(range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                          firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                          ch: ClickHouse = Depends(ch_dep)):
    """Every neighbor drop in the window with its likely cause (underlay tunnel, WAN, ICMP, restart, CPU, BFD or BGP-only)."""
    t0, t1 = _window(range, start, end)
    rep = await bgp.report(ch, s, t0, t1, firewall_id or None, correlate=True)
    drops = [{**d, "firewall_id": x["firewall_id"], "firewall_name": x["firewall_name"], "peer": x["peer"], "interface": x["interface"]}
             for x in rep["peers"] for d in x["down_periods"]]
    drops.sort(key=lambda d: d["start"], reverse=True)
    verdicts: dict[str, int] = {}
    for d in drops:
        verdicts[d.get("verdict") or "unknown"] = verdicts.get(d.get("verdict") or "unknown", 0) + 1
    return {"drops": drops, "verdicts": sorted(({"verdict": k, "count": v} for k, v in verdicts.items()), key=lambda x: -x["count"])}


# ------------------------------------------------------------------ non-FortiGate log sources


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._-]+$")
    kind: str = Field("windows", pattern=r"^(windows|cef|syslog)$")
    source_ips: list[str] = Field(min_length=1, max_length=20)
    site: str = Field("", max_length=64)
    enabled: bool = True
    description: str = Field("", max_length=2000)


def src_out(x: LogSource, n24: int = 0) -> dict:
    return {"id": x.id, "name": x.name, "kind": x.kind, "source_ips": x.source_ips, "site": x.site, "enabled": x.enabled,
            "description": x.description, "events_total": x.events_total, "events_24h": n24, "last_event_at": iso(x.last_event_at),
            "firewall_id": SOURCE_ID_BASE + x.id}


async def _check_ips(s: AsyncSession, ips: list[str], self_id: int | None = None) -> list[str]:
    out = []
    for ip in ips:
        try:
            out.append(str(ipaddress.ip_address(ip.strip())))
        except ValueError:
            raise HTTPException(422, f"invalid IP address: {ip}")
    taken = {i for f in (await s.execute(select(Firewall))).scalars() for i in [f.host, *(f.syslog_source_ips or [])]}
    clash = [i for i in out if i in taken]
    if clash:
        raise HTTPException(422, f"already used by a firewall: {', '.join(clash)}")
    for x in (await s.execute(select(LogSource))).scalars():
        if x.id != self_id and set(x.source_ips or []) & set(out):
            raise HTTPException(422, f"already used by log source {x.name}")
    return sorted(set(out))


@router.get("/log-sources")
async def list_sources(_: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    rows = (await s.execute(select(LogSource).order_by(LogSource.name))).scalars().all()
    counts = {}
    if rows:
        for r in await ch.aquery("SELECT firewall_id, sum(events) AS n FROM events_minute WHERE minute >= now() - INTERVAL 1 DAY "
                                 "AND firewall_id >= {b:UInt32} GROUP BY firewall_id", {"b": SOURCE_ID_BASE}):
            counts[int(r["firewall_id"]) - SOURCE_ID_BASE] = int(r["n"])
    return [src_out(x, counts.get(x.id, 0)) for x in rows]


@router.post("/log-sources", status_code=201)
async def create_source(body: SourceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(LogSource).where(LogSource.name == body.name))).first():
        raise HTTPException(409, "a log source with this name exists")
    x = LogSource(**{**body.model_dump(), "source_ips": await _check_ips(s, body.source_ips)}, created_by=user.username)
    s.add(x)
    await s.commit()
    await audit(s, request, user.username, "log_source_create", x.name, {"kind": x.kind, "ips": x.source_ips})
    return src_out(x)


@router.put("/log-sources/{sid}")
async def update_source(sid: int, body: SourceIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    x = await s.get(LogSource, sid)
    if not x:
        raise HTTPException(404, "not found")
    data = {**body.model_dump(), "source_ips": await _check_ips(s, body.source_ips, sid)}
    for k, v in data.items():
        setattr(x, k, v)
    await s.commit()
    await audit(s, request, user.username, "log_source_update", x.name, {"kind": x.kind, "ips": x.source_ips})
    return src_out(x)


@router.delete("/log-sources/{sid}")
async def delete_source(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    x = await s.get(LogSource, sid)
    if not x:
        raise HTTPException(404, "not found")
    await s.delete(x)
    await s.commit()
    await audit(s, request, user.username, "log_source_delete", x.name)
    return {"ok": True}
