"""APIs (Sentinel Grid): non-FortiGate log sources. (Firewall health, IPsec tunnels and BGP moved to api/netops.py, NMS.)"""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Firewall, LogSource, User
from ..db.pg import get_session
from ..ingest.generic import SOURCE_ID_BASE
from .deps import audit, ch_dep, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["ops"])


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._-]+$")
    kind: str = Field("windows", pattern=r"^(windows|cef|netdev|syslog|zeek|json|leef|linux)$")
    source_ips: list[str] = Field(min_length=1, max_length=20)
    site: str = Field("", max_length=64)
    enabled: bool = True
    description: str = Field("", max_length=2000)


def src_out(x: LogSource, n24: int = 0) -> dict:
    return {"id": x.id, "name": x.name, "kind": x.kind, "source_ips": x.source_ips, "site": x.site, "enabled": x.enabled,
            "description": x.description, "events_total": x.events_total, "events_24h": n24, "last_event_at": iso(x.last_event_at),
            "firewall_id": SOURCE_ID_BASE + x.id, "http_ingest": bool(x.token_hash), "token_hint": x.token_hint or ""}


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
