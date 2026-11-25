"""APIs: threat intel, assets, geo/ASN, VPN, compliance. (Configuration drift moved to api/netops.py, NMS.)"""
from __future__ import annotations

import csv
import io
import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..platform.eventquery import EventFilter
from ..analytics.ngen import geo_summary, hunt, ti_summary, vpn_summary
from ..compliance import compliance_status
from ..db.ch import ClickHouse
from ..db.models import Asset, TiFeed, TiIndicator, User
from ..db.pg import get_session
from ..enrich.feeds import MANUAL, fetch_feed
from ..platform.geoip import GeoResolver
from ..config import get_settings
from ..netguard import DestinationError, check_url_static
from .deps import audit, ch_dep, csv_safe, current_user, event_filter, iso, require_admin

router = APIRouter(prefix="/api", tags=["context"])


# ------------------------------------------------------------------ threat intel
def feed_out(f: TiFeed) -> dict:
    return {"id": f.id, "name": f.name, "url": f.url, "kind": f.kind, "category": f.category, "enabled": f.enabled, "builtin": f.builtin,
            "refresh_hours": f.refresh_hours, "last_fetch": iso(f.last_fetch), "last_success": iso(f.last_success),
            "last_status": f.last_status, "indicator_count": f.indicator_count, "auth_header": f.auth_header, "has_auth": bool(f.auth_ciphertext),
            "default_confidence": f.default_confidence, "expire_days": f.expire_days}


@router.get("/ti/feeds")
async def list_feeds(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return [feed_out(f) for f in (await s.execute(select(TiFeed).order_by(TiFeed.builtin.desc(), TiFeed.name))).scalars()]


class FeedIn(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    url: str = Field(pattern=r"^https://", max_length=1024)
    kind: str = Field(pattern=r"^(ip|cidr|domain|mixed|stix|taxii|misp|otx)$")
    category: str = Field("malicious", max_length=48)
    refresh_hours: int = Field(6, ge=1, le=168)
    # API key / token for the source: sent in `auth_header` (default per connector), stored encrypted, never returned
    auth_header: str = Field("", max_length=64, pattern=r"^[A-Za-z0-9-]*$")
    auth_value: str = Field("", max_length=4096)
    default_confidence: int = Field(50, ge=0, le=100)
    expire_days: int = Field(0, ge=0, le=3650)


@router.post("/ti/feeds", status_code=201)
async def add_feed(body: FeedIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        check_url_static(body.url, ("https",))
    except DestinationError as e:
        raise HTTPException(422, str(e))
    if (await s.execute(select(TiFeed).where(TiFeed.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "feed name exists")
    data = body.model_dump(exclude={"auth_value"})
    if body.auth_value:
        from ..enrich.connectors import DEFAULT_HEADER
        from ..security import TokenCipher
        data["auth_header"] = body.auth_header or DEFAULT_HEADER.get(body.kind, "Authorization")
        data["auth_ciphertext"] = TokenCipher().encrypt(body.auth_value)
    f = TiFeed(**data, enabled=True, builtin=False)
    s.add(f)
    await s.commit()
    await audit(s, request, admin.username, "ti_feed_add", body.name, {"url": body.url, "kind": body.kind, "auth": bool(body.auth_value)})
    return feed_out(f)


class FeedPatch(BaseModel):
    enabled: bool | None = None
    refresh_hours: int | None = Field(None, ge=1, le=168)
    default_confidence: int | None = Field(None, ge=0, le=100)
    expire_days: int | None = Field(None, ge=0, le=3650)


@router.put("/ti/feeds/{fid}")
async def update_feed(fid: int, body: FeedPatch, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    f = await s.get(TiFeed, fid)
    if not f:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    await s.commit()
    await audit(s, request, admin.username, "ti_feed_update", f.name, body.model_dump(exclude_unset=True))
    return feed_out(f)


@router.delete("/ti/feeds/{fid}")
async def delete_feed(fid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    f = await s.get(TiFeed, fid)
    if not f or f.builtin:
        raise HTTPException(400, "built-in feeds can be disabled but not deleted")
    await s.delete(f)
    await s.commit()
    await audit(s, request, admin.username, "ti_feed_delete", f.name)
    return {"ok": True}


@router.post("/ti/feeds/{fid}/refresh")
async def refresh_feed(fid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    f = await s.get(TiFeed, fid)
    if not f:
        raise HTTPException(404, "not found")
    status = await fetch_feed(s, f)
    await audit(s, request, admin.username, "ti_feed_refresh", f.name, {"status": status})
    return feed_out(f)


@router.get("/ti/manual")
async def manual_list(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    feed = (await s.execute(select(TiFeed).where(TiFeed.name == MANUAL))).scalar_one_or_none()
    if not feed:
        return []
    rows = (await s.execute(select(TiIndicator).where(TiIndicator.feed_id == feed.id).order_by(TiIndicator.added_at.desc()).limit(2000))).scalars()
    return [{"id": r.id, "indicator": r.indicator, "type": r.type, "note": r.note, "added_at": iso(r.added_at)} for r in rows]


class ManualIn(BaseModel):
    indicators: str = Field(min_length=1, max_length=200_000)
    note: str = Field("", max_length=255)


@router.post("/ti/manual")
async def manual_add(body: ManualIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    from ..analytics.ngen import parse_indicators
    ips, nets, doms = parse_indicators(body.indicators)
    feed = (await s.execute(select(TiFeed).where(TiFeed.name == MANUAL))).scalar_one()
    existing = {r for (r,) in (await s.execute(select(TiIndicator.indicator).where(TiIndicator.feed_id == feed.id))).all()}
    added = 0
    from ..enrich.connectors import normalize as ti_normalize
    extra = [n for n in (ti_normalize(tok) for tok in body.indicators.replace(",", " ").split()) if n and n[1] in ("url", "sha256", "sha1", "md5", "email", "asn")]
    for ind, typ in [(i, "ip") for i in ips] + [(n, "cidr") for n in nets] + [(d, "domain") for d in doms if "/" not in d] + extra:   # a URL is a url indicator, not a domain
        if ind not in existing:
            s.add(TiIndicator(feed_id=feed.id, indicator=ind, type=typ, note=body.note))
            existing.add(ind)
            added += 1
    feed.indicator_count = len(existing)
    await s.commit()
    await audit(s, request, admin.username, "ti_manual_add", MANUAL, {"added": added})
    return {"added": added, "total": len(existing), "note": "New events are matched within 5 minutes; use Hunt for past events."}


@router.delete("/ti/manual/{iid}")
async def manual_delete(iid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(TiIndicator, iid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    feed = await s.get(TiFeed, r.feed_id)
    if feed:
        feed.indicator_count = max(0, (feed.indicator_count or 1) - 1)
    await s.commit()
    await audit(s, request, admin.username, "ti_manual_delete", r.indicator)
    return {"ok": True}


class IndicatorPatch(BaseModel):
    false_positive: bool
    note: str | None = Field(None, max_length=255)


@router.get("/ti/indicators")
async def ti_indicators(q: str | None = Query(None, max_length=255), type: str | None = Query(None, pattern=r"^(ip|cidr|domain|url|sha256|sha1|md5|email|asn)$"),
                        feed_id: int | None = None, false_positive: bool | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                        _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Search the indicator store. The same indicator from several feeds is one row per feed (source attribution)."""
    from sqlalchemy import func
    cond = []
    if q:
        cond.append(TiIndicator.indicator.contains(q.strip().lower(), autoescape=True))
    if type:
        cond.append(TiIndicator.type == type)
    if feed_id:
        cond.append(TiIndicator.feed_id == feed_id)
    if false_positive is not None:
        cond.append(TiIndicator.false_positive.is_(false_positive))
    total = (await s.execute(select(func.count(TiIndicator.id)).where(*cond))).scalar() or 0
    rows = (await s.execute(select(TiIndicator, TiFeed.name, TiFeed.category, TiFeed.default_confidence).join(TiFeed, TiFeed.id == TiIndicator.feed_id)
                            .where(*cond).order_by(TiIndicator.added_at.desc(), TiIndicator.id.desc()).offset((page - 1) * size).limit(size))).all()
    now = datetime.now(timezone.utc)
    return {"total": total, "page": page, "size": size, "items": [
        {"id": r.id, "indicator": r.indicator, "type": r.type, "feed": name, "category": cat, "threat": r.threat, "note": r.note,
         "confidence": r.confidence if r.confidence is not None else dc, "confidence_from_source": r.confidence is not None,
         "first_seen": iso(r.first_seen), "last_seen": iso(r.last_seen), "added_at": iso(r.added_at), "expires_at": iso(r.expires_at),
         "expired": bool(r.expires_at and (r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)) <= now),
         "false_positive": r.false_positive, "fp_by": r.fp_by} for r, name, cat, dc in rows]}


@router.patch("/ti/indicators/{iid}")
async def ti_indicator_patch(iid: int, body: IndicatorPatch, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Analyst verdict. A false positive stops matching within 5 minutes and survives feed refreshes."""
    r = await s.get(TiIndicator, iid)
    if not r:
        raise HTTPException(404, "not found")
    r.false_positive, r.fp_by = body.false_positive, user.username if body.false_positive else ""
    if body.note is not None:
        r.note = body.note
    await s.commit()
    await audit(s, request, user.username, "ti_indicator_false_positive" if body.false_positive else "ti_indicator_restore", r.indicator)
    return {"ok": True}


@router.get("/ti/stats")
async def ti_stats(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from sqlalchemy import func
    now = datetime.now(timezone.utc)
    by_type = (await s.execute(select(TiIndicator.type, func.count(TiIndicator.id)).group_by(TiIndicator.type))).all()
    by_feed = (await s.execute(select(TiFeed.name, TiFeed.kind, TiFeed.category, func.count(TiIndicator.id)).join(TiIndicator, TiIndicator.feed_id == TiFeed.id, isouter=True)
                               .group_by(TiFeed.id).order_by(func.count(TiIndicator.id).desc()))).all()
    distinct = (await s.execute(select(func.count(func.distinct(TiIndicator.indicator))))).scalar() or 0
    total = sum(n for _t, n in by_type)
    fp = (await s.execute(select(func.count(TiIndicator.id)).where(TiIndicator.false_positive.is_(True)))).scalar() or 0
    expired = (await s.execute(select(func.count(TiIndicator.id)).where(TiIndicator.expires_at.is_not(None), TiIndicator.expires_at <= now))).scalar() or 0
    return {"total": total, "distinct": distinct, "in_several_feeds": total - distinct, "false_positives": fp, "expired": expired,
            "by_type": [{"type": t, "count": n} for t, n in sorted(by_type, key=lambda x: -x[1])],
            "by_feed": [{"feed": n, "kind": k, "category": c, "count": cnt} for n, k, c, cnt in by_feed],
            "matched_at_ingest": ["ip", "cidr", "domain", "url", "email", "asn"],
            "note": "File hashes are stored for search and retro-hunts; events carry no hash column, so they are not matched at ingest."}


@router.get("/ti/summary")
async def ti_sum(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await ti_summary(ch, f)


class HuntIn(BaseModel):
    indicators: str = Field(min_length=1, max_length=200_000)


@router.post("/ti/hunt")
async def ti_hunt(body: HuntIn, f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    try:
        return await hunt(ch, f, body.indicators)
    except ValueError as e:
        raise HTTPException(422, str(e))


# ------------------------------------------------------------------ assets
def asset_out(a: Asset) -> dict:
    return {"ip": a.ip, "hostname": a.hostname, "mac": a.mac, "os": a.os, "last_user": a.last_user, "users": a.users,
            "firewall_ids": a.firewall_ids, "criticality": a.criticality, "tags": a.tags, "owner": a.owner, "notes": a.notes,
            "source": a.source, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen)}


@router.get("/assets")
async def list_assets(q: str | None = Query(None, max_length=128), criticality: str | None = None, page: int = Query(1, ge=1),
                      size: int = Query(50, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(Asset)
    if q:
        like = f"%{q}%"
        qy = qy.where(or_(Asset.ip.ilike(like), Asset.hostname.ilike(like), Asset.mac.ilike(like), Asset.last_user.ilike(like), Asset.owner.ilike(like)))
    if criticality:
        qy = qy.where(Asset.criticality == criticality)
    total = (await s.execute(select(func.count()).select_from(qy.subquery()))).scalar_one()
    rows = (await s.execute(qy.order_by(Asset.last_seen.desc()).offset((page - 1) * size).limit(size))).scalars()
    counts = dict((await s.execute(select(Asset.criticality, func.count()).group_by(Asset.criticality))).all())
    return {"items": [asset_out(a) for a in rows], "total": total, "counts": counts}


@router.get("/assets/lookup")
async def lookup_assets(ips: list[str] = Query(default=[]), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from ..assets import asset_map
    m = await asset_map(s, ips[:200])
    return {ip: {"hostname": a.hostname, "criticality": a.criticality, "user": a.last_user} for ip, a in m.items()}


@router.get("/assets/{ip}")
async def get_asset(ip: str, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = (await s.execute(select(Asset).where(Asset.ip == ip))).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "asset not known")
    return asset_out(a)


class AssetIn(BaseModel):
    hostname: str | None = Field(None, max_length=255)
    criticality: str | None = Field(None, pattern=r"^(low|normal|high|critical)$")
    tags: list[str] | None = Field(None, max_length=20)
    owner: str | None = Field(None, max_length=128)
    notes: str | None = Field(None, max_length=4000)


@router.put("/assets/{ip}")
async def upsert_asset(ip: str, body: AssetIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, "invalid IP")
    a = (await s.execute(select(Asset).where(Asset.ip == ip))).scalar_one_or_none()
    if a is None:
        a = Asset(ip=ip, source="manual", users=[], firewall_ids=[], tags=[])
        s.add(a)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    await s.commit()
    await audit(s, request, admin.username, "asset_update", ip, body.model_dump(exclude_unset=True))
    return asset_out(a)


# ------------------------------------------------------------------ geo / VPN / compliance
@router.get("/geo/status")
async def geo_status(_: User = Depends(current_user)):
    g = GeoResolver(get_settings().geoip_dir)
    return {"available": g.available, "files": g.files, "dir": get_settings().geoip_dir,
            "note": "FortiGate srccountry/dstcountry are used when logged; add GeoLite2/DB-IP .mmdb files for ASN and coordinates."}


@router.get("/geo/summary")
async def geo_sum(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await geo_summary(ch, f)


@router.get("/vpn/summary")
async def vpn_sum(f: EventFilter = Depends(event_filter), _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    return await vpn_summary(ch, f)


@router.get("/compliance")
async def compliance(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await compliance_status(s)


@router.get("/compliance/export.csv")
async def compliance_csv(request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    c = await compliance_status(s)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["framework", "control", "title", "status", "evidence", "how_to_improve"])
    for fw in c["frameworks"]:
        for x in fw["controls"]:
            w.writerow([csv_safe(v) for v in (fw["framework"], x["id"], x["title"], x["status"], x["evidence"], x["how"])])
    w.writerow([])
    w.writerow(["generated_at", c["generated_at"], c["disclaimer"]])
    await audit(s, request, user.username, "compliance_export")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="compliance-evidence.csv"'})
