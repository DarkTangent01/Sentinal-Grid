"""APIs: user and identity analytics (VPN users and sessions, user↔IP↔device, auth failures, unusual logins,
administrator activity and account / privilege changes)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import identity
from ..analytics.filters import EventFilter
from ..db.ch import ClickHouse
from ..db.models import User
from .deps import ch_dep, current_user

router = APIRouter(prefix="/api/identity", tags=["identity"])
RANGE = r"^(1h|24h|7d|30d)$"


def _window(range_: str | None, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    try:
        t0, t1 = EventFilter(range=range_ or "7d", start=start, end=end).window()
    except ValueError as e:
        raise HTTPException(422, str(e))
    if t1 - t0 > timedelta(days=31):
        raise HTTPException(422, "time range is limited to 31 days")
    return t0, t1


@router.get("/overview")
async def overview(range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
                   firewall_id: list[int] = Query(default=[]), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    t0, t1 = _window(range, start, end)
    return await identity.overview(ch, t0, t1, firewall_id or None)


@router.get("/users/{name}")
async def user(name: str, range: str | None = Query("7d", pattern=RANGE), start: datetime | None = None, end: datetime | None = None,
               _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    name = name.strip()
    if not name or len(name) > 255:
        raise HTTPException(422, "invalid user name")
    t0, t1 = _window(range, start, end)
    d = await identity.user_detail(ch, name, t0, t1)
    if d is None:
        raise HTTPException(404, "no authentication activity for this user in the selected range")
    return d


@router.get("/who")
async def who(ip: str = Query(min_length=2, max_length=64), at: datetime | None = None, _: User = Depends(current_user),
              ch: ClickHouse = Depends(ch_dep)):
    """Which user had this IP (VPN-assigned, public or client address) around a moment (default: the last 7 days)."""
    if at is not None and at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    t1 = at + timedelta(hours=12) if at else datetime.now(timezone.utc)
    t0 = (at - timedelta(days=1)) if at else t1 - timedelta(days=7)
    evs = await identity.auth_events(ch, t0, t1)
    sess = identity.sessions(evs, t1)
    hits = [s for s in sess if ip in (s["assigned_ip"], s["src_ip"], s["client_ip"])]
    if at:
        a = at.isoformat()
        hits = [s for s in hits if s["start"] <= a and (s["end"] is None or s["end"] >= a)] or hits
    return {"ip": ip, "sessions": hits[:50]}
