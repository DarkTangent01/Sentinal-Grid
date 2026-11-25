"""APIs (shared by Sentinel NMS and Sentinel Grid): the identity index (app/platform/identity.py).

User names, host names and MAC addresses are personal data. They are shown to administrators, to Sentinel Grid users
(identity security is part of the SIEM) and to NMS users whose role includes traffic-sensitive data; everyone else sees
device type, vendor and connection point only.
"""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import HostIdentity, User
from ..db.pg import get_session
from ..platform import identity as I
from ..products import products_of
from .deps import current_user, iso

router = APIRouter(prefix="/api/identities", tags=["identities"])
SENSITIVE_NMS_ROLES = {"nms_admin", "network_engineer", "site_admin", "auditor", "super_admin"}


def sensitive(user: User) -> bool:
    if user.role == "admin" or "grid" in products_of(user):
        return True
    return bool(SENSITIVE_NMS_ROLES & set(getattr(user, "nms_roles", None) or []))


@router.get("/ip/{addr}")
async def by_ip(addr: str, days: int = Query(7, ge=1, le=30), user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Who and what is behind an address now, and every MAC / user it was bound to over `days`."""
    try:
        ip = str(ipaddress.ip_address(addr))
    except ValueError:
        raise HTTPException(422, "not an IP address")
    sens = sensitive(user)
    cur = (await I.identities(s, [ip], sensitive=sens)).get(ip)
    tl = await I.timeline(s, ip, days)
    if not sens:
        tl["users"] = []
        for m in tl["macs"]:
            m["mac"] = ""
    return {"ip": ip, "current": cur, "timeline": tl, "sensitive": sens}


@router.post("/lookup")
async def lookup(body: dict, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Batch: {"ips": [...]} (at most 500) → ip → identity."""
    ips = body.get("ips") if isinstance(body, dict) else None
    if not isinstance(ips, list) or len(ips) > 500:
        raise HTTPException(422, "ips: a list of at most 500 addresses")
    return await I.identities(s, [str(x) for x in ips], sensitive=sensitive(user))


DEVICE_SORT = {"last_seen": HostIdentity.last_seen, "first_seen": HostIdentity.first_seen, "vendor": HostIdentity.vendor,
               "device_type": HostIdentity.device_type}


@router.get("/devices")
async def devices(q: str | None = Query(None, max_length=64), device_type: str | None = Query(None, max_length=48), vendor: str | None = Query(None, max_length=64),
                  site: str | None = Query(None, max_length=128), vlan: int | None = Query(None, ge=1, le=4094), randomized: bool | None = None,
                  sort: str = Query("-last_seen", max_length=24), limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
                  user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Device inventory built from the identity index (every MAC seen by any source)."""
    sens = sensitive(user)
    stmt = select(HostIdentity)
    if q:
        like = f"%{q.strip().lower()}%"
        conds = [func.lower(HostIdentity.vendor).like(like), func.lower(HostIdentity.device_type).like(like), HostIdentity.last_ip.like(like),
                 func.lower(HostIdentity.switch).like(like), func.lower(HostIdentity.ap).like(like)]
        if sens:
            conds += [HostIdentity.mac.like(like), func.lower(HostIdentity.hostname).like(like), func.lower(HostIdentity.last_user).like(like)]
        stmt = stmt.where(or_(*conds))
    if device_type:
        stmt = stmt.where(HostIdentity.device_type == device_type)
    if vendor:
        stmt = stmt.where(func.lower(HostIdentity.vendor).like(f"%{vendor.lower()}%"))
    if site:
        stmt = stmt.where(HostIdentity.site == site)
    if vlan is not None:
        stmt = stmt.where(HostIdentity.vlan == vlan)
    if randomized is not None:
        stmt = stmt.where(HostIdentity.randomized.is_(randomized))
    k = sort.lstrip("-+")
    if k not in DEVICE_SORT:
        raise HTTPException(422, f"cannot sort by {k}")
    col = DEVICE_SORT[k]
    total = (await s.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await s.execute(stmt.order_by(col.desc() if sort.startswith("-") else col.asc()).limit(limit).offset(offset))).scalars().all()
    types = dict((await s.execute(select(HostIdentity.device_type, func.count()).group_by(HostIdentity.device_type))).all())
    return {"total": int(total), "types": {(t or "Unclassified"): n for t, n in types.items()}, "items": [{
        "mac": r.mac if sens else "", "vendor": r.vendor, "vendor_source": r.vendor_source, "randomized": r.randomized, "device_type": r.device_type,
        "confidence": r.device_type_confidence, "evidence": r.device_evidence, "os": r.os, "hostname": r.hostname if sens else "",
        "last_ip": r.last_ip, "user": r.last_user if sens else "", "switch": r.switch, "port": r.port, "vlan": r.vlan, "ap": r.ap, "ssid": r.ssid,
        "site": r.site, "sources": r.sources, "first_seen": iso(r.first_seen), "last_seen": iso(r.last_seen)} for r in rows], "sensitive": sens}
