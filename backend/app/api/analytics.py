import csv
import io
import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import queries as Q
from ..analytics.filters import EventFilter
from ..db.ch import ClickHouse
from ..db.models import Alert, Firewall, User
from ..db.pg import get_session
from .deps import iso, audit, ch_dep, csv_safe, current_user, event_filter

router = APIRouter(prefix="/api", tags=["analytics"])


def _bad(e: Exception):
    raise HTTPException(422, str(e))


@router.get("/analytics/kpis")
async def kpis(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep),
               s: AsyncSession = Depends(get_session)):
    try:
        k = await Q.kpis(ch, f)
    except ValueError as e:
        _bad(e)
    t0, t1 = f.window()
    k["security_alerts"] = (await s.execute(select(func.count(Alert.id)).where(Alert.last_seen >= t0, Alert.first_seen < t1,
                                                                            Alert.status != "suppressed"))).scalar_one()
    k["open_alerts"] = (await s.execute(select(func.count(Alert.id)).where(Alert.status.in_(["new", "investigating"])))).scalar_one()
    fws = (await s.execute(select(Firewall).where(Firewall.enabled.is_(True)))).scalars().all()
    k["firewalls_connected"] = sum(1 for x in fws if x.api_status == "ok")
    k["firewalls_disconnected"] = sum(1 for x in fws if x.api_status != "ok" and not x.is_demo)
    k["firewalls_total"] = len(fws)
    k["window"] = {"start": t0.isoformat(), "end": t1.isoformat()}
    k["generated_at"] = datetime.now(timezone.utc).isoformat()
    return k


@router.get("/analytics/timeseries/traffic")
async def ts_traffic(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.traffic_timeseries(ch, f)


@router.get("/analytics/timeseries/{cat}")
async def ts_cat(cat: str, f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    if cat not in ("dns", "web", "security", "system"):
        raise HTTPException(404, "unknown category")
    return await Q.category_timeseries(ch, f, cat)


@router.get("/analytics/top/{dimension}")
async def top(dimension: str, category: str | None = None, metric: str = "count", limit: int = Query(10, ge=1, le=100),
              f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    try:
        return await Q.top(ch, f, dimension, category=category, metric=metric, limit=limit)
    except ValueError as e:
        _bad(e)


@router.get("/analytics/sources")
async def sources(sort: str = "count", limit: int = Query(25, ge=1, le=100), f: EventFilter = Depends(event_filter),
                  _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.top_sources(ch, f, sort, limit)


@router.get("/analytics/destinations")
async def destinations(sort: str = "count", limit: int = Query(25, ge=1, le=100), rdns: bool = False,
                       f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.top_destinations(ch, f, sort, limit, rdns)


@router.get("/analytics/ports")
async def ports(sort: str = "count", limit: int = Query(25, ge=1, le=100), f: EventFilter = Depends(event_filter),
                _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.top_ports(ch, f, sort, limit)


@router.get("/analytics/web")
async def web(limit: int = Query(25, ge=1, le=100), f: EventFilter = Depends(event_filter), _: User = Depends(current_user),
              ch: ClickHouse = Depends(ch_dep)):
    return await Q.web_summary(ch, f, limit)


@router.get("/analytics/dns")
async def dns(limit: int = Query(25, ge=1, le=100), f: EventFilter = Depends(event_filter), _: User = Depends(current_user),
              ch: ClickHouse = Depends(ch_dep)):
    return await Q.dns_summary(ch, f, limit)


@router.get("/analytics/dns/indicators")
async def dns_ind(repeat_threshold: int = Query(100, ge=2), long_qname: int = Query(52, ge=10, le=253),
                  entropy: float = Query(3.8, ge=1, le=6), z: float = Query(3.0, ge=1, le=20),
                  f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.dns_indicators(ch, f, repeat_threshold=repeat_threshold, long_qname=long_qname, entropy=entropy, z=z)


@router.get("/analytics/security")
async def security(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await Q.security_summary(ch, f)


@router.get("/events")
async def events(page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500), sort: str = "event_time",
                 order: str = Query("desc", pattern="^(asc|desc)$"), f: EventFilter = Depends(event_filter),
                 _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    try:
        return await Q.list_events(ch, f, page, size, sort, order)
    except ValueError as e:
        _bad(e)


@router.get("/events/export.csv")
async def export(request: Request, max_rows: int = Query(50_000, ge=1, le=100_000), f: EventFilter = Depends(event_filter),
                 user: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep), s: AsyncSession = Depends(get_session)):
    try:
        rows = await Q.export_rows(ch, f, max_rows)
    except ValueError as e:
        _bad(e)
    await audit(s, request, user.username, "export_csv", "events", {"rows": len(rows)})
    cols = [c.strip() for c in Q.EVENT_LIST_COLUMNS.split(",")]

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        yield buf.getvalue()
        for r in rows:
            buf.seek(0)
            buf.truncate()
            w.writerow([csv_safe(v) for v in (r.get(c) for c in cols)])
            yield buf.getvalue()

    name = f"events_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.csv"
    return StreamingResponse(gen(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/events/{event_id}")
async def event(event_id: str, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    if not event_id.isalnum() or len(event_id) > 64:
        raise HTTPException(422, "invalid id")
    ev = await Q.get_event(ch, event_id)
    if not ev:
        raise HTTPException(404, "not found")
    return ev


@router.get("/investigate/ip/{ip}")
async def investigate(ip: str, f: EventFilter = Depends(event_filter), _: User = Depends(current_user),
                      ch: ClickHouse = Depends(ch_dep), s: AsyncSession = Depends(get_session)):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, "invalid IP address")
    out = await Q.investigate_ip(ch, f, ip)
    alerts = (await s.execute(select(Alert).where(or_(Alert.src_ip == ip, Alert.dst_ip == ip)).order_by(Alert.last_seen.desc()).limit(50))).scalars()
    out["alerts"] = [{"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "last_seen": iso(a.last_seen),
                      "event_count": a.event_count} for a in alerts]
    return out


@router.get("/events/{event_id}/context")
async def event_context(event_id: str, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep), s: AsyncSession = Depends(get_session)):
    """Everything an analyst checks next for one event: assets, threat intel, watchlists, related alerts/incidents,
    the matching firewall policy and the rest of the same session."""
    from datetime import timedelta
    from ..db.models import Asset, FirewallPolicy, Incident, TiFeed, TiIndicator, Watchlist, WatchlistItem
    if not event_id.isalnum() or len(event_id) > 64:
        raise HTTPException(422, "invalid id")
    ev = await Q.get_event(ch, event_id)
    if not ev:
        raise HTTPException(404, "not found")
    ips = [x for x in (ev.get("src_ip"), ev.get("dst_ip")) if x]
    out: dict = {"event_id": event_id, "entities": {}}
    for role, ip in (("source", ev.get("src_ip")), ("destination", ev.get("dst_ip"))):
        if not ip:
            continue
        a = (await s.execute(select(Asset).where(Asset.ip == ip))).scalars().first()
        ti = (await s.execute(select(TiFeed.name, TiFeed.category, TiIndicator.note).join(TiFeed, TiFeed.id == TiIndicator.feed_id)
                              .where(TiIndicator.indicator == ip).limit(5))).all()
        wl = [n for (n,) in (await s.execute(select(Watchlist.name).join(WatchlistItem, WatchlistItem.watchlist_id == Watchlist.id)
                                             .where(WatchlistItem.value == ip))).all()]
        out["entities"][role] = {
            "ip": ip, "asset": {"hostname": a.hostname, "criticality": a.criticality, "owner": a.owner, "os": a.os, "last_user": a.last_user} if a else None,
            "threat_intel": [{"feed": n, "category": c, "note": note} for n, c, note in ti], "watchlists": wl,
            "country": ev.get("src_country" if role == "source" else "dst_country") or "", "as_org": ev.get("dst_as_org", "") if role == "destination" else ""}
    since = datetime.now(timezone.utc) - timedelta(days=7)
    alerts = (await s.execute(select(Alert).where(or_(Alert.src_ip.in_(ips), Alert.dst_ip.in_(ips)), Alert.last_seen >= since)
                              .order_by(Alert.last_seen.desc()).limit(10))).scalars().all() if ips else []
    out["alerts"] = [{"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "last_seen": iso(a.last_seen)} for a in alerts]
    incs = (await s.execute(select(Incident).where(Incident.entity.in_(ips + ([ev["user"]] if ev.get("user") else [])))
                            .order_by(Incident.last_seen.desc()).limit(5))).scalars().all() if ips else []
    out["incidents"] = [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status} for i in incs]
    pol = None
    if ev.get("policy_id") is not None and ev.get("firewall_id"):
        p = (await s.execute(select(FirewallPolicy).where(FirewallPolicy.firewall_id == int(ev["firewall_id"]),
                                                          FirewallPolicy.policyid == int(ev["policy_id"]),
                                                          FirewallPolicy.vdom == (ev.get("vdom") or "root")))).scalars().first()
        if p:
            pol = {"policyid": p.policyid, "name": p.name, "action": p.action, "status": p.status, "logtraffic": p.logtraffic, "vdom": p.vdom,
                   "firewall_id": p.firewall_id, "usage": (p.assessment or {}).get("state"), "shadow": (p.analysis or {}).get("worst")}
    out["policy"] = pol
    if ev.get("session_id"):
        et = datetime.fromisoformat(str(ev["event_time"]).replace("Z", "").replace(" ", "T"))
        et = et if et.tzinfo else et.replace(tzinfo=timezone.utc)
        rows = await ch.aquery("SELECT category, count() AS n FROM events WHERE session_id = {sid:UInt64} AND firewall_id = {fw:UInt32} "
                               "AND event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)} GROUP BY category",
                               {"sid": int(ev["session_id"]), "fw": int(ev["firewall_id"]),
                                "t0": et - timedelta(hours=1), "t1": et + timedelta(hours=1)})
        out["session"] = {r["category"]: int(r["n"]) for r in rows}
    return out
