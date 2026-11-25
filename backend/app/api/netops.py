"""APIs (Sentinel NMS): firewall health (resources, reboots, FortiAnalyzer, log feeds), site-to-site IPsec tunnels, BGP peers,
and FortiGate configuration drift. Moved out of the SIEM routers (docs/architecture/MIGRATION_PLAN.md phase 3); the
paths are unchanged."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import bgp, fwhealth, vpnmon
from ..db.ch import ClickHouse
from ..db.models import ConfigSnapshot, Firewall, User
from ..db.pg import get_session
from ..platform.eventquery import EventFilter
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["nms-firewalls"])
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


# ------------------------------------------------------------------ configuration drift
@router.get("/drift")
async def drift_list(firewall_id: int | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(ConfigSnapshot)
    if firewall_id:
        qy = qy.where(ConfigSnapshot.firewall_id == firewall_id)
    snaps = (await s.execute(qy.order_by(ConfigSnapshot.collected_at.desc()).limit(200))).scalars().all()
    fws = {f.id: f for f in (await s.execute(select(Firewall))).scalars()}
    latest: dict = {}
    for sn in snaps:
        latest.setdefault((sn.firewall_id, sn.vdom), sn)
    from ..drift import assess_risks
    current = [{"firewall_id": k[0], "firewall": fws[k[0]].name if k[0] in fws else "?", "vdom": k[1], "snapshot_id": sn.id,
                "collected_at": iso(sn.collected_at), "risks": assess_risks(sn.data, None), "errors": sn.errors}
               for k, sn in latest.items()]
    return {"current": current,
            "snapshots": [{"id": sn.id, "firewall_id": sn.firewall_id, "firewall": fws[sn.firewall_id].name if sn.firewall_id in fws else "?",
                           "vdom": sn.vdom, "collected_at": iso(sn.collected_at), "changes": len(sn.changes or []),
                           "risks": len([r for r in sn.risks or [] if not r.get("baseline")]), "baseline": not sn.changes and any(r.get("baseline") for r in sn.risks or [])}
                          for sn in snaps]}


@router.get("/drift/{sid}")
async def drift_detail(sid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    sn = await s.get(ConfigSnapshot, sid)
    if not sn:
        raise HTTPException(404, "not found")
    return {"id": sn.id, "firewall_id": sn.firewall_id, "vdom": sn.vdom, "collected_at": iso(sn.collected_at), "changes": sn.changes,
            "risks": sn.risks, "errors": sn.errors, "tables": {k: (len(v) if isinstance(v, dict) else 1) for k, v in (sn.data or {}).items()}}


# ------------------------------------------------------------------ BGP critical prefixes (NMS setting)
class PrefixIn(BaseModel):
    prefix: str = Field(min_length=3, max_length=64)
    label: str = Field("", max_length=128)


class PrefixesIn(BaseModel):
    items: list[PrefixIn] = Field(default_factory=list, max_length=2000)


@router.get("/bgp/critical-prefixes")
async def critical_prefixes(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"items": await bgp.critical_prefixes(s)}


@router.put("/bgp/critical-prefixes")
async def set_critical_prefixes(body: PrefixesIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    from ..bgp_analysis import _net
    from ..db.models import WanSetting
    bad = [x.prefix for x in body.items if _net(x.prefix) is None]
    if bad:
        raise HTTPException(422, f"not an IP network: {', '.join(bad[:5])}")
    row = (await s.execute(select(WanSetting).order_by(WanSetting.id).limit(1))).scalars().first()
    if row is None:
        row = WanSetting(data={})
        s.add(row)
    row.data = {**(row.data or {}), bgp.CRITICAL_KEY: [{"prefix": str(_net(x.prefix)), "label": x.label} for x in body.items]}
    row.updated_by = user.username
    await s.commit()
    await audit(s, request, user.username, "bgp_critical_prefixes", detail={"count": len(body.items)})
    return {"items": row.data[bgp.CRITICAL_KEY]}
