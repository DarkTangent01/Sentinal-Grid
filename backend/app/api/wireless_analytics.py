"""APIs: Wireless → historical client analytics (daily SSID / AP statistics, hourly distribution, rankings, roaming,
client connection history). Read-only. Definitions and data limits: app/wireless/client_analytics.py and
docs/WIRELESS_CLIENT_ANALYTICS.md.

Common filters: start_date / end_date (calendar days in the user's display timezone, inclusive), controller_id, site,
ssid, ap_id / ap_name, frequency_band; tables add sort / order / page / page_size and format=csv.
"""

import csv
import io
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import User, WirelessClient, WirelessClientSession
from ..db.pg import get_session
from ..wireless import client_analytics as A
from ..wireless import service as W
from .deps import ch_dep, csv_safe, current_user

router = APIRouter(prefix="/api/wireless/analytics", tags=["wireless-analytics"])
_CACHE: dict = {}
CACHE_S = 60          # rollups change every 5 minutes; a minute's cache spares repeated identical page loads
MAC = r"^[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}$"


class Filters:
    def __init__(self, start_date: date | None = Query(None), end_date: date | None = Query(None),
                 controller_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128),
                 ssid: list[str] = Query(default=[]), ap_id: list[int] = Query(default=[]), ap_name: list[str] = Query(default=[]),
                 frequency_band: list[str] = Query(default=[])):
        self.start_date, self.end_date, self.controller_id, self.site = start_date, end_date, controller_id, site
        self.ssid, self.ap_id, self.ap_name = [x for x in ssid if x][:50], ap_id[:500], [x for x in ap_name if x][:500]
        self.band = [b for b in frequency_band if b in A.BANDS]

    def key(self) -> tuple:
        return (self.start_date, self.end_date, tuple(self.controller_id), self.site, tuple(self.ssid), tuple(self.ap_id), tuple(self.ap_name),
                tuple(self.band))


async def _scope(s: AsyncSession, user: User, f: Filters) -> tuple[A.Scope, dict, dict]:
    try:
        tz = A.check_tz(getattr(user, "timezone", None))
    except Exception:
        tz = "UTC"
    today = datetime.now(ZoneInfo(tz)).date()
    end = f.end_date or today
    start = f.start_date or end - timedelta(days=6)
    try:
        t0, t1, days, note = A.window(start, end, tz)
    except ValueError as e:
        raise HTTPException(422, str(e))
    wlcs, ids, aps, _ = await W.load(s, f.controller_id or None, f.site)
    ap_ids = None
    if f.ap_id or f.ap_name:
        names = {n.lower() for n in f.ap_name}
        ap_ids = [i for i, a in aps.items() if i in f.ap_id or (a.name or "").lower() in names or a.mac.lower() in names]
    elif f.site:
        ap_ids = list(aps)
    sc = A.Scope(tz=tz, t0=t0, t1=t1, wlc_ids=ids, ssids=f.ssid, ap_ids=ap_ids, bands=f.band, days=days, tz_note=note)
    return sc, wlcs, aps


async def _cached(key: tuple, make):
    hit = _CACHE.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    val = await make()
    if len(_CACHE) > 500:
        _CACHE.clear()
    _CACHE[key] = (time.monotonic() + CACHE_S, val)
    return val


def _meta(sc: A.Scope) -> dict:
    return {"timezone": sc.tz, "start": sc.t0.isoformat(), "end": sc.t1.isoformat(), "days": sc.days, "timezone_note": sc.tz_note or None}


def _csv(name: str, cols: list[str], rows: list[dict]) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(r.get(c)) for c in cols])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


@router.get("/filters")
async def filters(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    wlcs, ids, aps, _ = await W.load(s)
    ssids = sorted({x for (x,) in (await s.execute(select(WirelessClientSession.ssid).where(WirelessClientSession.ssid != "").distinct())).all()}
                   | {x for (x,) in (await s.execute(select(WirelessClient.ssid).where(WirelessClient.ssid != "").distinct())).all()})
    return {"controllers": [{"id": w.id, "name": w.name, "site": w.site or ""} for w in wlcs.values()],
            "sites": sorted({a.site for a in aps.values() if a.site} | {w.site for w in wlcs.values() if w.site}),
            "ssids": ssids, "aps": sorted([{"id": a.id, "name": a.name or a.mac, "mac": a.mac, "wlc_id": a.wlc_id, "site": a.site or ""}
                                           for a in aps.values()], key=lambda x: x["name"]),
            "bands": list(A.BANDS), "timezone": getattr(user, "timezone", None) or "UTC"}


@router.get("/ssid/daily")
async def ssid_daily(f: Filters = Depends(), period: str = Query("day", pattern="^(day|week|month)$"), sort: str = Query("date", pattern="^(date|ssid|unique_clients|sessions|peak_clients|avg_clients)$"),
                     order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=1000),
                     format: str = Query("json", pattern="^(json|csv)$"), user: User = Depends(current_user),
                     s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sc, _, _ = await _scope(s, user, f)
    if format == "csv":
        res = await A.daily_ssid(ch, sc, sort, order, 1, 100_000, period)
        return _csv("ssid-daily-clients", ["day", "ssid", "unique_clients", "sessions", "peak_clients", "avg_clients"], res["items"])
    res = await _cached(("ssid_daily", sc.tz, f.key(), sort, order, page, page_size, period),
                        lambda: A.daily_ssid(ch, sc, sort, order, page, page_size, period))
    cov = await _cached(("coverage", sc.tz, f.key(), period), lambda: A.coverage(ch, sc, period))
    return {**res, **_meta(sc), "coverage": cov}


@router.get("/ap/daily")
async def ap_daily(f: Filters = Depends(), by_ssid: bool = True, period: str = Query("day", pattern="^(day|week|month)$"),
                   sort: str = Query("date", pattern="^(date|ap_name|ssid|unique_clients|sessions|peak_clients|avg_clients)$"),
                   order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=1000),
                   format: str = Query("json", pattern="^(json|csv)$"), user: User = Depends(current_user),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sc, _, aps = await _scope(s, user, f)
    if format == "csv":
        res = await A.daily_ap(ch, sc, aps, by_ssid, sort, order, 1, 100_000, period)
        return _csv("ap-daily-clients", ["day", "ap_name", "ap_mac", "ssid", "unique_clients", "sessions", "peak_clients", "avg_clients"], res["items"])
    res = await _cached(("ap_daily", sc.tz, f.key(), by_ssid, sort, order, page, page_size, period),
                        lambda: A.daily_ap(ch, sc, aps, by_ssid, sort, order, page, page_size, period))
    return {**res, **_meta(sc)}


@router.get("/hourly")
async def hourly(f: Filters = Depends(), group: str = Query("ssid", pattern="^(ssid|ap|none)$"), limit: int = Query(8, ge=1, le=20),
                 expected_weeks: int = Query(0, ge=0, le=8), user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                 ch: ClickHouse = Depends(ch_dep)):
    sc, _, aps = await _scope(s, user, f)
    res = await _cached(("hourly", sc.tz, f.key(), group, limit, expected_weeks), lambda: A.hourly(ch, sc, group, limit, expected_weeks))
    if group == "ap":
        for x in res["series"]:
            a = aps.get(int(x["key"]))
            x["label"] = a.name if a else f"AP {x['key']}"
    return {**res, **_meta(sc)}


@router.get("/rankings")
async def rankings(f: Filters = Depends(), top: int = Query(10, ge=1, le=50), user: User = Depends(current_user),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sc, _, aps = await _scope(s, user, f)
    return {**await _cached(("rankings", sc.tz, f.key(), top), lambda: A.rankings(ch, sc, aps, top)), **_meta(sc)}


@router.get("/ap/distribution")
async def ap_distribution(f: Filters = Depends(), limit: int = Query(30, ge=1, le=500), user: User = Depends(current_user),
                          s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sc, _, aps = await _scope(s, user, f)
    return {**await _cached(("dist", sc.tz, f.key(), limit), lambda: A.ap_distribution(ch, sc, aps, limit)), **_meta(sc)}


@router.get("/roaming")
async def roaming(f: Filters = Depends(), top: int = Query(15, ge=1, le=50), user: User = Depends(current_user),
                  s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sc, _, aps = await _scope(s, user, f)
    return {**await _cached(("roaming", sc.tz, f.key(), top), lambda: A.roaming(ch, sc, aps, top)), **_meta(sc)}


@router.get("/clients/{mac}/history")
async def client_history(mac: str, f: Filters = Depends(), page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                         user: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    import re
    if not re.match(MAC, mac):
        raise HTTPException(422, "invalid MAC address")
    m = re.sub(r"[^0-9a-f]", "", mac.lower())
    mac = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    sc, wlcs, aps = await _scope(s, user, f)
    q = select(WirelessClientSession).where(WirelessClientSession.mac == mac, WirelessClientSession.started_at < sc.t1,
                                            or_(WirelessClientSession.ended_at.is_(None), WirelessClientSession.ended_at >= sc.t0))
    if sc.wlc_ids:
        q = q.where(WirelessClientSession.wlc_id.in_(sc.wlc_ids))
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    rows = (await s.execute(q.order_by(WirelessClientSession.started_at.desc()).limit(page_size).offset((page - 1) * page_size))).scalars().all()
    cur = (await s.execute(select(WirelessClient).where(WirelessClient.mac == mac))).scalars().all()
    seen = {c.session_id: c.last_seen for c in cur if c.session_id}
    now = datetime.now(timezone.utc)
    name = lambda i: (aps[i].name or aps[i].mac) if i in aps else None  # noqa: E731

    def iso(v):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat() if v else None

    def aware(v):
        return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)
    sessions = []
    for x in rows:
        end = aware(x.ended_at) or aware(seen.get(x.id)) or now
        sessions.append({"id": x.id, "controller": wlcs[x.wlc_id].name if x.wlc_id in wlcs else str(x.wlc_id), "site": x.site, "ssid": x.ssid,
                         "ip": x.ip, "vlan": x.vlan, "band": x.band, "first_ap": name(x.first_ap_id), "last_ap": name(x.last_ap_id),
                         "aps": [name(i) or f"AP {i}" for i in (x.aps or [])], "started_at": iso(x.started_at), "start_source": x.start_source,
                         "ended_at": iso(x.ended_at), "open": x.ended_at is None, "end_reason": x.end_reason, "disconnect_reason": x.disconnect_reason,
                         "duration_s": int((end - aware(x.started_at)).total_seconds()), "roams": x.roams, "band_changes": x.band_changes})
    events = await A.client_events(ch, sc, mac)
    for e in events:
        e["ap"], e["from_ap"] = name(e.get("ap_id")), name(e.get("from_ap_id"))
    return {"mac": mac, "sessions": sessions, "total": total, "page": page, "page_size": page_size, "events": events, **_meta(sc),
            "note": "Session start is the controller's association time when it reports one (start_source 'controller'); the end is the last "
                    "poll that listed the client, so the client left before the next poll."}
