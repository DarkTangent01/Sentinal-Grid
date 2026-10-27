"""APIs: pipeline search, custom detections, watchlists, hunting + bookmarks, workbooks, automation, entity graph."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..alerts.custom import evaluate as evaluate_detection
from ..alerts.engine import CUSTOM_PREFIX
from ..alerts.rules import TACTICS
from ..analytics.filters import EventFilter
from ..analytics.pipeline import PipelineError, compile_pipeline, run_pipeline, watchlist_names
from ..automation import ACTIONS, TRIGGERS, execute, matches, facts, validate_actions
from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import (Alert, AlertRule, Asset, AutomationRule, AutomationRun, Bookmark, HuntingQuery, Incident,
                         IncidentComment, NotificationChannel, User, Watchlist, WatchlistItem, Workbook)
from ..db.pg import get_session
from ..watchlists import KINDS, MAX_ITEMS, NAME, load_watchlists, parse_items
from .deps import audit, ch_dep, csv_safe, current_user, iso, require_admin

router = APIRouter(prefix="/api", tags=["hunt"])
RANGE = r"^(5m|15m|1h|24h|7d|30d)$"
# heavy ad-hoc queries share ClickHouse with ingestion and the dashboards: cap concurrent pipeline runs
_SEARCH_SLOTS = asyncio.Semaphore(4)


def _window(range_: str | None, start: datetime | None, end: datetime | None, firewall_id: list[int] | None = None) -> EventFilter:
    f = EventFilter(range=range_ or "24h", start=start, end=end, firewall_id=list(firewall_id or []))
    try:
        t0, t1 = f.window()
    except ValueError as e:
        raise HTTPException(422, str(e))
    if t1 - t0 > timedelta(days=get_settings().max_query_range_days):
        raise HTTPException(422, f"time range is limited to {get_settings().max_query_range_days} days")
    return f


async def _run(s: AsyncSession, ch: ClickHouse, query: str, f: EventFilter, max_rows: int | None = None) -> dict:
    wl = await load_watchlists(s, watchlist_names(query))
    async with _SEARCH_SLOTS:
        try:
            return await run_pipeline(ch, query, f, wl, max_rows)
        except PipelineError as e:
            raise HTTPException(422, str(e))
        except Exception as e:  # ClickHouse type errors, timeouts: report them as a query problem, not a 500
            msg = str(e).split("\n")[0][:400]
            raise HTTPException(422, f"query failed: {msg}")


async def _validate(s: AsyncSession, query: str) -> None:
    try:
        compile_pipeline(query, await load_watchlists(s, watchlist_names(query)))
    except PipelineError as e:
        raise HTTPException(422, str(e))


# ------------------------------------------------------------------ pipeline search
class SearchIn(BaseModel):
    query: str = Field("", max_length=4000)
    range: str | None = Field("24h", pattern=RANGE)
    start: datetime | None = None
    end: datetime | None = None
    firewall_id: list[int] = Field(default_factory=list)
    max_rows: int = Field(1000, ge=1, le=10_000)


@router.post("/search")
async def search(body: SearchIn, _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    f = _window(body.range, body.start, body.end, body.firewall_id)
    res = await _run(s, ch, body.query, f, body.max_rows)
    t0, t1 = f.window()
    return {**res, "window": {"start": t0.isoformat(), "end": t1.isoformat()}}


@router.post("/search/validate")
async def search_validate(body: dict, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = str(body.get("query", ""))[:4000]
    try:
        p = compile_pipeline(q, await load_watchlists(s, watchlist_names(q)))
        return {"valid": True, "kind": p.kind}
    except PipelineError as e:
        return {"valid": False, "error": str(e)}


@router.post("/search/export.csv")
async def search_export(body: SearchIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                        ch: ClickHouse = Depends(ch_dep)):
    res = await _run(s, ch, body.query, _window(body.range, body.start, body.end, body.firewall_id), 10_000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(res["columns"])
    for r in res["rows"]:
        w.writerow([csv_safe(", ".join(map(str, v)) if isinstance(v, list) else v) for v in (r.get(c) for c in res["columns"])])
    await audit(s, request, user.username, "search_export", body.query[:200], {"rows": len(res["rows"])})
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="search.csv"'})


# ------------------------------------------------------------------ custom detections
class DetectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    severity: str = Field("medium", pattern=r"^(informational|low|medium|high|critical)$")
    enabled: bool = True
    query: str = Field(min_length=1, max_length=4000)
    lookback_minutes: int = Field(60, ge=1, le=20160)
    interval_minutes: int = Field(5, ge=1, le=1440)
    trigger_op: str = Field("gt", pattern=r"^(gt|ge|eq|ne|lt|le)$")
    trigger_count: int = Field(0, ge=0, le=1_000_000)
    grouping: str = Field("per_row", pattern=r"^(per_row|single)$")
    entity_fields: list[str] = Field(default_factory=list, max_length=5)
    explanation: str = Field("", max_length=500)
    tactic: str = Field("", max_length=16)
    techniques: list[str] = Field(default_factory=list, max_length=10)


PARAM_KEYS = ("query", "lookback_minutes", "interval_minutes", "trigger_op", "trigger_count", "grouping", "entity_fields", "explanation")


def _mitre(body: DetectionIn) -> dict:
    if body.tactic and body.tactic not in TACTICS:
        raise HTTPException(422, f"unknown tactic {body.tactic}")
    techs = [t.strip().upper() for t in body.techniques if t.strip()]
    for t in techs:
        if not (t.startswith("T") and t[1:].replace(".", "").isdigit()):
            raise HTTPException(422, f"invalid technique id {t}")
    return {"tactic": body.tactic, "tactic_name": TACTICS.get(body.tactic, ""), "techniques": techs} if body.tactic else {}


def det_out(r: AlertRule, stats: dict | None = None) -> dict:
    p = r.params or {}
    return {"id": r.id, "key": r.key, "name": r.name, "description": r.description, "severity": r.severity, "enabled": r.enabled,
            **{k: p.get(k) for k in PARAM_KEYS}, "tactic": (r.mitre or {}).get("tactic", ""),
            "techniques": (r.mitre or {}).get("techniques", []), "updated_at": iso(r.updated_at), **(stats or {})}


@router.get("/detections")
async def list_detections(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rules = (await s.execute(select(AlertRule).where(AlertRule.key.like(f"{CUSTOM_PREFIX}%")).order_by(AlertRule.name))).scalars().all()
    since = datetime.now(timezone.utc) - timedelta(days=7)
    stats = {k: (n, last) for k, n, last in (await s.execute(
        select(Alert.rule_key, func.count(Alert.id), func.max(Alert.last_seen)).where(Alert.rule_key.like(f"{CUSTOM_PREFIX}%"),
               Alert.last_seen >= since).group_by(Alert.rule_key))).all()}
    return [det_out(r, {"alerts_7d": stats.get(r.key, (0, None))[0], "last_alert": iso(stats.get(r.key, (0, None))[1])}) for r in rules]


@router.post("/detections/preview")
async def preview_detection(body: DetectionIn, _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                            ch: ClickHouse = Depends(ch_dep)):
    await _validate(s, body.query)
    async with _SEARCH_SLOTS:
        try:
            dets, info = await evaluate_detection(ch, s, datetime.now(timezone.utc), {k: getattr(body, k) for k in PARAM_KEYS}, name=body.name)
        except PipelineError as e:
            raise HTTPException(422, str(e))
        except Exception as e:
            raise HTTPException(422, f"query failed: {str(e).splitlines()[0][:400]}")
    return {**info, "alerts": [{"group_key": d.group_key, "count": d.count, "explanation": d.explanation, "src_ip": d.src_ip,
                                "dst_ip": d.dst_ip, "first_seen": d.first_seen.isoformat(), "last_seen": d.last_seen.isoformat()}
                               for d in dets[:50]]}


@router.post("/detections", status_code=201)
async def create_detection(body: DetectionIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    await _validate(s, body.query)
    r = AlertRule(key=f"{CUSTOM_PREFIX}{secrets.token_hex(5)}", name=body.name, description=body.description, severity=body.severity,
                  enabled=body.enabled, params={k: getattr(body, k) for k in PARAM_KEYS}, mitre=_mitre(body))
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "detection_create", r.key, {"name": r.name})
    return det_out(r)


async def _detection(s: AsyncSession, rid: int) -> AlertRule:
    r = await s.get(AlertRule, rid)
    if not r or not r.key.startswith(CUSTOM_PREFIX):
        raise HTTPException(404, "not found")
    return r


@router.put("/detections/{rid}")
async def update_detection(rid: int, body: DetectionIn, request: Request, user: User = Depends(require_admin),
                           s: AsyncSession = Depends(get_session)):
    r = await _detection(s, rid)
    await _validate(s, body.query)
    r.name, r.description, r.severity, r.enabled = body.name, body.description, body.severity, body.enabled
    r.params = {k: getattr(body, k) for k in PARAM_KEYS}
    r.mitre = _mitre(body)
    await s.commit()
    await audit(s, request, user.username, "detection_update", r.key, {"name": r.name})
    return det_out(r)


@router.delete("/detections/{rid}")
async def delete_detection(rid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await _detection(s, rid)
    await s.delete(r)
    await s.commit()
    await audit(s, request, user.username, "detection_delete", r.key, {"name": r.name})
    return {"ok": True}


@router.get("/mitre/tactics")
async def mitre_tactics(_: User = Depends(current_user)):
    return [{"id": k, "name": v} for k, v in TACTICS.items()]


# ------------------------------------------------------------------ watchlists
class WatchlistIn(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    description: str = Field("", max_length=1000)
    kind: str = Field("ip", pattern=r"^(ip|domain|user|string)$")


class ItemsIn(BaseModel):
    text: str = Field(max_length=5_000_000)
    mode: str = Field("append", pattern=r"^(append|replace)$")
    ttl_hours: int = Field(0, ge=0, le=24 * 365)


def wl_out(w: Watchlist, count: int = 0) -> dict:
    return {"id": w.id, "name": w.name, "description": w.description, "kind": w.kind, "created_by": w.created_by,
            "created_at": iso(w.created_at), "updated_at": iso(w.updated_at), "items": count}


@router.get("/watchlists")
async def list_watchlists(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    counts = dict((await s.execute(select(WatchlistItem.watchlist_id, func.count()).group_by(WatchlistItem.watchlist_id))).all())
    return [wl_out(w, counts.get(w.id, 0)) for w in (await s.execute(select(Watchlist).order_by(Watchlist.name))).scalars()]


@router.post("/watchlists", status_code=201)
async def create_watchlist(body: WatchlistIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if not NAME.match(body.name):
        raise HTTPException(422, "name must start with a letter and use only letters, digits and _ (it is used in queries)")
    if (await s.execute(select(Watchlist.id).where(Watchlist.name == body.name))).first():
        raise HTTPException(409, "a watchlist with this name exists")
    w = Watchlist(**body.model_dump(), created_by=user.username)
    s.add(w)
    await s.commit()
    await audit(s, request, user.username, "watchlist_create", w.name)
    return wl_out(w)


async def _wl(s: AsyncSession, wid: int) -> Watchlist:
    w = await s.get(Watchlist, wid)
    if not w:
        raise HTTPException(404, "not found")
    return w


@router.put("/watchlists/{wid}")
async def update_watchlist(wid: int, body: WatchlistIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    w = await _wl(s, wid)
    if body.kind != w.kind and (await s.execute(select(func.count()).where(WatchlistItem.watchlist_id == wid))).scalar_one():
        raise HTTPException(422, "the kind of a non-empty watchlist cannot change")
    if body.name != w.name:
        raise HTTPException(422, "watchlists cannot be renamed (queries and detections reference the name)")
    w.description, w.kind = body.description, body.kind
    await s.commit()
    await audit(s, request, user.username, "watchlist_update", w.name)
    return wl_out(w)


@router.delete("/watchlists/{wid}")
async def delete_watchlist(wid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    w = await _wl(s, wid)
    await s.execute(delete(WatchlistItem).where(WatchlistItem.watchlist_id == wid))
    await s.delete(w)
    await s.commit()
    await audit(s, request, user.username, "watchlist_delete", w.name)
    return {"ok": True}


@router.get("/watchlists/{wid}/items")
async def watchlist_items(wid: int, q: str | None = Query(None, max_length=255), page: int = Query(1, ge=1),
                          size: int = Query(100, ge=1, le=500), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _wl(s, wid)
    qy = select(WatchlistItem).where(WatchlistItem.watchlist_id == wid)
    if q:
        qy = qy.where(or_(WatchlistItem.value.ilike(f"%{q}%"), WatchlistItem.label.ilike(f"%{q}%")))
    total = (await s.execute(select(func.count()).select_from(qy.subquery()))).scalar_one()
    rows = (await s.execute(qy.order_by(WatchlistItem.value).offset((page - 1) * size).limit(size))).scalars()
    return {"total": total, "items": [{"id": i.id, "value": i.value, "label": i.label, "added_by": i.added_by,
                                       "expires_at": iso(i.expires_at), "created_at": iso(i.created_at)} for i in rows]}


@router.post("/watchlists/{wid}/items")
async def add_watchlist_items(wid: int, body: ItemsIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    w = await _wl(s, wid)
    items, errors = parse_items(w.kind, body.text)
    if body.mode == "replace":
        await s.execute(delete(WatchlistItem).where(WatchlistItem.watchlist_id == wid))
        existing: set[str] = set()
    else:
        existing = {v for (v,) in (await s.execute(select(WatchlistItem.value).where(WatchlistItem.watchlist_id == wid))).all()}
    new = [(v, l) for v, l in items if v not in existing]
    if len(existing) + len(new) > MAX_ITEMS:
        raise HTTPException(422, f"a watchlist holds at most {MAX_ITEMS:,} items")
    exp = datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours) if body.ttl_hours else None
    s.add_all([WatchlistItem(watchlist_id=wid, value=v, label=l, added_by=user.username, expires_at=exp) for v, l in new])
    w.updated_at = datetime.now(timezone.utc)
    await s.commit()
    await audit(s, request, user.username, "watchlist_items", w.name, {"mode": body.mode, "added": len(new), "errors": len(errors)})
    return {"added": len(new), "skipped_existing": len(items) - len(new), "errors": errors[:50], "error_count": len(errors)}


@router.delete("/watchlists/{wid}/items/{iid}")
async def delete_watchlist_item(wid: int, iid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    w = await _wl(s, wid)
    i = await s.get(WatchlistItem, iid)
    if not i or i.watchlist_id != wid:
        raise HTTPException(404, "not found")
    await s.delete(i)
    await s.commit()
    await audit(s, request, user.username, "watchlist_item_delete", w.name, {"value": i.value})
    return {"ok": True}


@router.get("/watchlists/{wid}/export.csv")
async def export_watchlist(wid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await _wl(s, wid)
    buf = io.StringIO()
    out = csv.writer(buf)
    out.writerow(["value", "label"])
    for v, l in (await s.execute(select(WatchlistItem.value, WatchlistItem.label).where(WatchlistItem.watchlist_id == wid)
                                 .order_by(WatchlistItem.value))).all():
        out.writerow([csv_safe(v), csv_safe(l)])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="watchlist-{w.name}.csv"'})


# ------------------------------------------------------------------ hunting + bookmarks
class HuntIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    query: str = Field(min_length=1, max_length=4000)
    range: str = Field("24h", pattern=RANGE)
    tactic: str = Field("", max_length=16)
    techniques: list[str] = Field(default_factory=list, max_length=10)


def hunt_out(h: HuntingQuery) -> dict:
    return {"id": h.id, "key": h.key, "name": h.name, "description": h.description, "query": h.query, "range": h.range,
            "tactic": h.tactic, "tactic_name": TACTICS.get(h.tactic, ""), "techniques": h.techniques or [], "builtin": h.builtin,
            "author": h.author, "last_run": iso(h.last_run), "last_count": h.last_count, "last_error": h.last_error}


@router.get("/hunting")
async def list_hunts(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(HuntingQuery).order_by(HuntingQuery.builtin.desc(), HuntingQuery.tactic, HuntingQuery.name))).scalars()
    return [hunt_out(h) for h in rows]


@router.post("/hunting", status_code=201)
async def create_hunt(body: HuntIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _validate(s, body.query)
    if body.tactic and body.tactic not in TACTICS:
        raise HTTPException(422, "unknown tactic")
    h = HuntingQuery(**body.model_dump(), builtin=False, author=user.username)
    s.add(h)
    await s.commit()
    await audit(s, request, user.username, "hunt_create", h.name)
    return hunt_out(h)


async def _hunt(s: AsyncSession, hid: int, user: User | None = None) -> HuntingQuery:
    h = await s.get(HuntingQuery, hid)
    if not h:
        raise HTTPException(404, "not found")
    if user is not None and (h.builtin or (h.author != user.username and user.role != "admin")):
        raise HTTPException(403, "built-in hunts are read-only; others can be changed by their author or an administrator")
    return h


@router.put("/hunting/{hid}")
async def update_hunt(hid: int, body: HuntIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    h = await _hunt(s, hid, user)
    await _validate(s, body.query)
    for k, v in body.model_dump().items():
        setattr(h, k, v)
    await s.commit()
    await audit(s, request, user.username, "hunt_update", h.name)
    return hunt_out(h)


@router.delete("/hunting/{hid}")
async def delete_hunt(hid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    h = await _hunt(s, hid, user)
    await s.delete(h)
    await s.commit()
    await audit(s, request, user.username, "hunt_delete", h.name)
    return {"ok": True}


async def _run_hunt(s: AsyncSession, ch: ClickHouse, h: HuntingQuery, range_: str | None) -> dict:
    try:
        res = await _run(s, ch, h.query, _window(range_ or h.range, None, None))
        h.last_count, h.last_error = len(res["rows"]), None
    except HTTPException as e:
        h.last_count, h.last_error, res = None, str(e.detail), None
    h.last_run = datetime.now(timezone.utc)
    return {"id": h.id, "count": h.last_count, "error": h.last_error, "truncated": bool(res and res["truncated"])}


@router.post("/hunting/{hid}/run")
async def run_hunt(hid: int, range: str | None = Query(None, pattern=RANGE), _: User = Depends(current_user),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    h = await _hunt(s, hid)
    out = await _run_hunt(s, ch, h, range)
    await s.commit()
    return out


@router.post("/hunting/run-all")
async def run_all_hunts(range: str | None = Query(None, pattern=RANGE), _: User = Depends(current_user),
                        s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Runs every hunt one after another (the search semaphore already bounds ClickHouse load) and records result counts."""
    out = []
    for h in (await s.execute(select(HuntingQuery).order_by(HuntingQuery.id))).scalars().all():
        out.append(await _run_hunt(s, ch, h, range))
        await s.commit()
    return out


class BookmarkIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=0, max_length=4000)
    window_start: datetime | None = None
    window_end: datetime | None = None
    columns: list[str] = Field(default_factory=list, max_length=100)
    rows: list[dict] = Field(default_factory=list, max_length=100)
    notes: str = Field("", max_length=5000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    incident_id: int | None = None


class BookmarkPatch(BaseModel):
    notes: str | None = Field(None, max_length=5000)
    incident_id: int | None = None
    tags: list[str] | None = Field(None, max_length=20)


def bm_out(b: Bookmark) -> dict:
    return {"id": b.id, "name": b.name, "query": b.query, "window_start": iso(b.window_start), "window_end": iso(b.window_end),
            "columns": b.columns, "rows": b.rows, "notes": b.notes, "tags": b.tags or [], "incident_id": b.incident_id,
            "created_by": b.created_by, "created_at": iso(b.created_at)}


async def _attach(s: AsyncSession, b: Bookmark, iid: int, user: str) -> None:
    inc = await s.get(Incident, iid)
    if not inc:
        raise HTTPException(404, "incident not found")
    b.incident_id = iid
    inc.evidence = [*(inc.evidence or []), {"type": "bookmark", "ref": str(b.id), "label": b.name, "added_by": user,
                                            "at": datetime.now(timezone.utc).isoformat()}]
    s.add(IncidentComment(incident_id=iid, author=user, kind="evidence",
                          body=f"Hunting bookmark #{b.id} '{b.name}' attached ({len(b.rows)} row(s)). Query: {b.query[:500]}"))


@router.get("/bookmarks")
async def list_bookmarks(incident_id: int | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(Bookmark).order_by(Bookmark.created_at.desc()).limit(500)
    if incident_id is not None:
        qy = qy.where(Bookmark.incident_id == incident_id)
    return [bm_out(b) for b in (await s.execute(qy)).scalars()]


@router.post("/bookmarks", status_code=201)
async def create_bookmark(body: BookmarkIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    data = body.model_dump(exclude={"incident_id"})
    data["rows"] = [{str(k)[:64]: v for k, v in list(r.items())[:60]} for r in data["rows"]]
    b = Bookmark(**data, created_by=user.username)
    s.add(b)
    await s.flush()
    if body.incident_id:
        await _attach(s, b, body.incident_id, user.username)
    await s.commit()
    await audit(s, request, user.username, "bookmark_create", b.name, {"incident_id": body.incident_id})
    return bm_out(b)


@router.patch("/bookmarks/{bid}")
async def update_bookmark(bid: int, body: BookmarkPatch, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    b = await s.get(Bookmark, bid)
    if not b:
        raise HTTPException(404, "not found")
    if body.notes is not None:
        b.notes = body.notes
    if body.tags is not None:
        b.tags = body.tags
    if body.incident_id and body.incident_id != b.incident_id:
        await _attach(s, b, body.incident_id, user.username)
    await s.commit()
    return bm_out(b)


@router.delete("/bookmarks/{bid}")
async def delete_bookmark(bid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    b = await s.get(Bookmark, bid)
    if not b:
        raise HTTPException(404, "not found")
    if b.created_by != user.username and user.role != "admin":
        raise HTTPException(403, "only the creator or an administrator can delete a bookmark")
    await s.delete(b)
    await s.commit()
    return {"ok": True}


# ------------------------------------------------------------------ workbooks
VIZ = ("table", "line", "area", "bar", "column", "pie", "kpi")


class PanelIn(BaseModel):
    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=1, max_length=128)
    query: str = Field(max_length=4000)
    viz: str = Field("table", pattern=r"^(table|line|area|bar|column|pie|kpi)$")
    width: int = Field(6, ge=2, le=12)
    range: str | None = Field(None, pattern=RANGE)


class WorkbookIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    range: str = Field("24h", pattern=RANGE)
    panels: list[PanelIn] = Field(default_factory=list, max_length=30)
    shared: bool = True


def wb_out(w: Workbook) -> dict:
    return {"id": w.id, "key": w.key, "name": w.name, "description": w.description, "range": w.range, "panels": w.panels or [],
            "owner": w.owner, "shared": w.shared, "template": w.owner == "system", "updated_at": iso(w.updated_at)}


async def _check_panels(s: AsyncSession, panels: list[PanelIn]) -> None:
    ids = [p.id for p in panels]
    if len(set(ids)) != len(ids):
        raise HTTPException(422, "panel ids must be unique")
    for p in panels:
        try:
            compile_pipeline(p.query, await load_watchlists(s, watchlist_names(p.query)))
        except PipelineError as e:
            raise HTTPException(422, f"panel '{p.title}': {e}")


def _can_see(w: Workbook, user: User) -> bool:
    return w.shared or w.owner == user.username or user.role == "admin"


def _can_edit(w: Workbook, user: User) -> bool:
    return user.role == "admin" or (w.owner == user.username and w.owner != "system")


@router.get("/workbooks")
async def list_workbooks(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(Workbook).order_by(Workbook.name))).scalars()
    return [{**wb_out(w), "can_edit": _can_edit(w, user)} for w in rows if _can_see(w, user)]


@router.get("/workbooks/{wid}")
async def get_workbook(wid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await s.get(Workbook, wid)
    if not w or not _can_see(w, user):
        raise HTTPException(404, "not found")
    return {**wb_out(w), "can_edit": _can_edit(w, user)}


@router.post("/workbooks", status_code=201)
async def create_workbook(body: WorkbookIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _check_panels(s, body.panels)
    w = Workbook(name=body.name, description=body.description, range=body.range, panels=[p.model_dump() for p in body.panels],
                 shared=body.shared, owner=user.username)
    s.add(w)
    await s.commit()
    await audit(s, request, user.username, "workbook_create", w.name)
    return {**wb_out(w), "can_edit": True}


@router.put("/workbooks/{wid}")
async def update_workbook(wid: int, body: WorkbookIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await s.get(Workbook, wid)
    if not w or not _can_see(w, user):
        raise HTTPException(404, "not found")
    if not _can_edit(w, user):
        raise HTTPException(403, "only the owner or an administrator can edit this workbook (clone it to make your own copy)")
    await _check_panels(s, body.panels)
    w.name, w.description, w.range, w.shared = body.name, body.description, body.range, body.shared
    w.panels = [p.model_dump() for p in body.panels]
    await s.commit()
    await audit(s, request, user.username, "workbook_update", w.name)
    return {**wb_out(w), "can_edit": True}


@router.post("/workbooks/{wid}/clone", status_code=201)
async def clone_workbook(wid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await s.get(Workbook, wid)
    if not w or not _can_see(w, user):
        raise HTTPException(404, "not found")
    c = Workbook(name=f"{w.name} (copy)"[:128], description=w.description, range=w.range, panels=w.panels, shared=False, owner=user.username)
    s.add(c)
    await s.commit()
    await audit(s, request, user.username, "workbook_clone", c.name, {"from": w.id})
    return {**wb_out(c), "can_edit": True}


@router.delete("/workbooks/{wid}")
async def delete_workbook(wid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await s.get(Workbook, wid)
    if not w or not _can_see(w, user):
        raise HTTPException(404, "not found")
    if not _can_edit(w, user):
        raise HTTPException(403, "only the owner or an administrator can delete this workbook")
    await s.delete(w)
    await s.commit()
    await audit(s, request, user.username, "workbook_delete", w.name)
    return {"ok": True}


# ------------------------------------------------------------------ automation
class AutomationIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    enabled: bool = True
    priority: int = Field(100, ge=0, le=10_000)
    trigger: str = Field(pattern=r"^(alert\.created|incident\.created|incident\.escalated)$")
    conditions: dict = Field(default_factory=dict)
    actions: list[dict] = Field(default_factory=list)
    stop_processing: bool = False


COND_KEYS = {"min_severity", "rule_keys", "tactics", "entity_types", "sites", "asset_criticality", "title_contains"}


def au_out(r: AutomationRule) -> dict:
    return {"id": r.id, "name": r.name, "description": r.description, "enabled": r.enabled, "priority": r.priority, "trigger": r.trigger,
            "conditions": r.conditions or {}, "actions": r.actions or [], "stop_processing": r.stop_processing,
            "created_by": r.created_by, "run_count": r.run_count, "last_run": iso(r.last_run), "updated_at": iso(r.updated_at)}


def _check_automation(body: AutomationIn) -> None:
    extra = set(body.conditions) - COND_KEYS
    if extra:
        raise HTTPException(422, f"unknown condition(s): {', '.join(sorted(extra))}")
    try:
        validate_actions(body.actions)
    except (ValueError, PipelineError) as e:
        raise HTTPException(422, str(e))


@router.get("/automation/meta")
async def automation_meta(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rules = (await s.execute(select(AlertRule.key, AlertRule.name).order_by(AlertRule.name))).all()
    return {"triggers": list(TRIGGERS), "actions": list(ACTIONS), "tactics": [{"id": k, "name": v} for k, v in TACTICS.items()],
            "rules": [{"key": k, "name": n} for k, n in rules],
            "users": [u for (u,) in (await s.execute(select(User.username).where(User.is_active.is_(True)).order_by(User.username))).all()],
            "channels": [{"id": i, "name": n} for i, n in (await s.execute(select(NotificationChannel.id, NotificationChannel.name))).all()],
            "watchlists": [{"id": i, "name": n, "kind": k} for i, n, k in (await s.execute(select(Watchlist.id, Watchlist.name, Watchlist.kind))).all()]}


@router.get("/automation/rules")
async def list_automation(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(AutomationRule).order_by(AutomationRule.trigger, AutomationRule.priority, AutomationRule.id))).scalars()
    return [au_out(r) for r in rows]


@router.post("/automation/rules", status_code=201)
async def create_automation(body: AutomationIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    _check_automation(body)
    r = AutomationRule(**body.model_dump(), created_by=user.username)
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "automation_create", r.name)
    return au_out(r)


@router.put("/automation/rules/{rid}")
async def update_automation(rid: int, body: AutomationIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(AutomationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    _check_automation(body)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await s.commit()
    await audit(s, request, user.username, "automation_update", r.name)
    return au_out(r)


@router.delete("/automation/rules/{rid}")
async def delete_automation(rid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(AutomationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    await audit(s, request, user.username, "automation_delete", r.name)
    return {"ok": True}


class AutomationTest(BaseModel):
    target_type: str = Field(pattern=r"^(alert|incident)$")
    target_id: int
    apply: bool = False


@router.post("/automation/rules/{rid}/test")
async def test_automation(rid: int, body: AutomationTest, request: Request, user: User = Depends(require_admin),
                          s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Dry run by default: shows whether the conditions match and what each action would do. apply=true runs it for real."""
    r = await s.get(AutomationRule, rid)
    target = await s.get(Incident if body.target_type == "incident" else Alert, body.target_id)
    if not r or not target:
        raise HTTPException(404, "rule or target not found")
    ok, why = matches(r.conditions, facts(target))
    run = await execute(s, r, f"manual.{body.target_type}", target, ch, dry=not body.apply)
    if body.apply:
        await s.commit()
        await audit(s, request, user.username, "automation_run", r.name, {"target": f"{body.target_type}#{body.target_id}"})
    else:
        await s.rollback()
    return {"conditions_match": ok, "reason": why, "status": run.status, "results": run.results}


@router.get("/automation/runs")
async def automation_runs(rule_id: int | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                          _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    qy = select(AutomationRun)
    if rule_id:
        qy = qy.where(AutomationRun.rule_id == rule_id)
    total = (await s.execute(select(func.count()).select_from(qy.subquery()))).scalar_one()
    rows = (await s.execute(qy.order_by(AutomationRun.at.desc()).offset((page - 1) * size).limit(size))).scalars()
    return {"total": total, "items": [{"id": x.id, "rule_id": x.rule_id, "rule_name": x.rule_name, "at": iso(x.at), "trigger": x.trigger,
                                       "target_type": x.target_type, "target_id": x.target_id, "status": x.status,
                                       "results": x.results} for x in rows]}


# ------------------------------------------------------------------ entity graph
@router.get("/entity/graph")
async def entity_graph(kind: str = Query(pattern=r"^(ip|user|domain)$"), value: str = Query(min_length=1, max_length=255),
                       range: str = Query("24h", pattern=RANGE), _: User = Depends(current_user),
                       s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Investigation graph around one entity: who it talked to, what it resolved, users, firewalls, alerts and incidents."""
    value = value.strip()
    if kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(422, "invalid IP address")
    elif kind == "domain":
        value = value.lower().rstrip(".")
    t0, t1 = _window(range, None, None).window()
    p = {"t0": t0, "t1": t1, "v": value}
    tw = "event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)}"
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid, typ, label, **kw):
        n = nodes.setdefault(nid, {"id": nid, "type": typ, "label": label, "weight": 0, **kw})
        n["weight"] = max(n["weight"], kw.get("weight", 0))
        return nid

    def edge(a, b, label, weight, **kw):
        edges.append({"source": a, "target": b, "label": label, "weight": int(weight), **kw})

    root = node(f"{kind}:{value}", kind, value, root=True)

    async def q(sql):
        async with _SEARCH_SLOTS:
            return await ch.aquery(sql, p)

    if kind == "ip":
        outs = await q(f"SELECT dst_ip AS peer, count() AS n, sum(sent_bytes) AS sent, countIf(action IN ('deny','block')) AS denied, "
                       f"groupUniqArray(5)(dst_port) AS ports, any(dst_country) AS cc FROM events WHERE {tw} AND src_ip = {{v:String}} "
                       f"AND dst_ip != '' GROUP BY peer ORDER BY n DESC LIMIT 15")
        for r in outs:
            nid = node(f"ip:{r['peer']}", "ip", r["peer"], country=r["cc"], weight=r["n"])
            edge(root, nid, f"{', '.join(str(x) for x in r['ports'] if x is not None)}", r["n"], denied=int(r["denied"]), bytes=int(r["sent"]))
        ins = await q(f"SELECT src_ip AS peer, count() AS n, countIf(action IN ('deny','block')) AS denied, groupUniqArray(5)(dst_port) AS ports "
                      f"FROM events WHERE {tw} AND dst_ip = {{v:String}} AND src_ip != '' GROUP BY peer ORDER BY n DESC LIMIT 10")
        for r in ins:
            nid = node(f"ip:{r['peer']}", "ip", r["peer"], weight=r["n"])
            edge(nid, root, f"{', '.join(str(x) for x in r['ports'] if x is not None)}", r["n"], denied=int(r["denied"]))
        doms = await q(f"SELECT cutToFirstSignificantSubdomain(if(dns_qname != '', dns_qname, hostname)) AS d, count() AS n FROM events "
                       f"WHERE {tw} AND src_ip = {{v:String}} AND (dns_qname != '' OR hostname != '') GROUP BY d HAVING d != '' "
                       f"ORDER BY n DESC LIMIT 10")
        for r in doms:
            edge(root, node(f"domain:{r['d']}", "domain", r["d"], weight=r["n"]), "resolved/visited", r["n"])
        users = await q(f"SELECT user AS u, count() AS n FROM events WHERE {tw} AND src_ip = {{v:String}} AND user != '' GROUP BY u ORDER BY n DESC LIMIT 5")
        for r in users:
            edge(node(f"user:{r['u'].lower()}", "user", r["u"], weight=r["n"]), root, "logged on", r["n"])
        fws = await q(f"SELECT firewall_name AS f, count() AS n FROM events WHERE {tw} AND (src_ip = {{v:String}} OR dst_ip = {{v:String}}) "
                      f"GROUP BY f ORDER BY n DESC LIMIT 5")
        a = (await s.execute(select(Asset).where(Asset.ip == value))).scalars().first()
        if a:
            nodes[root].update({"hostname": a.hostname, "criticality": a.criticality, "owner": a.owner})
    elif kind == "user":
        hosts = await q(f"SELECT src_ip AS h, count() AS n, any(src_country) AS cc FROM events WHERE {tw} AND lower(user) = lower({{v:String}}) "
                        f"AND src_ip != '' GROUP BY h ORDER BY n DESC LIMIT 15")
        for r in hosts:
            edge(root, node(f"ip:{r['h']}", "ip", r["h"], country=r["cc"], weight=r["n"]), "used", r["n"])
        dsts = await q(f"SELECT dst_ip AS d, count() AS n FROM events WHERE {tw} AND lower(user) = lower({{v:String}}) AND dst_ip != '' "
                       f"GROUP BY d ORDER BY n DESC LIMIT 10")
        for r in dsts:
            edge(root, node(f"ip:{r['d']}", "ip", r["d"], weight=r["n"]), "accessed", r["n"])
        fws = await q(f"SELECT firewall_name AS f, count() AS n FROM events WHERE {tw} AND lower(user) = lower({{v:String}}) GROUP BY f ORDER BY n DESC LIMIT 5")
    else:
        clients = await q(f"SELECT src_ip AS c, count() AS n FROM events WHERE {tw} AND (dns_qname = {{v:String}} OR endsWith(dns_qname, concat('.', {{v:String}})) "
                          f"OR lower(hostname) = {{v:String}} OR endsWith(lower(hostname), concat('.', {{v:String}}))) AND src_ip != '' "
                          f"GROUP BY c ORDER BY n DESC LIMIT 15")
        for r in clients:
            edge(node(f"ip:{r['c']}", "ip", r["c"], weight=r["n"]), root, "queried/visited", r["n"])
        resolved = await q(f"SELECT arrayJoin(dns_resolved) AS a, count() AS n FROM events WHERE {tw} AND category = 'dns' AND "
                           f"(dns_qname = {{v:String}} OR endsWith(dns_qname, concat('.', {{v:String}}))) GROUP BY a ORDER BY n DESC LIMIT 10")
        for r in resolved:
            edge(root, node(f"ip:{r['a']}", "ip", r["a"], weight=r["n"]), "resolves to", r["n"])
        fws = []
    for r in fws:
        edge(node(f"firewall:{r['f']}", "firewall", r["f"], weight=r["n"]), root, "observed by", r["n"])
    # alerts and incidents that mention the entity
    since = t0 - timedelta(days=7)
    if kind == "ip":
        cond = or_(Alert.src_ip == value, Alert.dst_ip == value)
    else:
        cond = or_(Alert.group_key == value, Alert.group_key.like(f"{value}|%"))
    for al in (await s.execute(select(Alert).where(cond, Alert.last_seen >= since).order_by(Alert.last_seen.desc()).limit(10))).scalars():
        edge(root, node(f"alert:{al.id}", "alert", al.name, severity=al.severity, ref=al.id, status=al.status), "alert", al.event_count or 1)
    for inc in (await s.execute(select(Incident).where(Incident.entity == value).order_by(Incident.last_seen.desc()).limit(5))).scalars():
        edge(root, node(f"incident:{inc.id}", "incident", f"#{inc.id} {inc.title}", severity=inc.severity, ref=inc.id, status=inc.status),
             "incident", inc.alert_count or 1)
    now = datetime.now(timezone.utc)
    live = or_(WatchlistItem.expires_at.is_(None), WatchlistItem.expires_at > now)
    wl_hits = {n for (n,) in (await s.execute(select(Watchlist.name).join(WatchlistItem, WatchlistItem.watchlist_id == Watchlist.id)
                                              .where(func.lower(WatchlistItem.value) == value.lower(), live))).all()}
    if kind == "ip":
        ipv = ipaddress.ip_address(value)
        for n, net in (await s.execute(select(Watchlist.name, WatchlistItem.value).join(WatchlistItem, WatchlistItem.watchlist_id == Watchlist.id)
                                       .where(Watchlist.kind == "ip", WatchlistItem.value.like("%/%"), live))).all():
            try:
                if ipv in ipaddress.ip_network(net):
                    wl_hits.add(n)
            except ValueError:
                continue
    wl_hits = sorted(wl_hits)
    nodes[root]["watchlists"] = wl_hits
    return {"root": root, "nodes": list(nodes.values()), "edges": edges, "window": {"start": t0.isoformat(), "end": t1.isoformat()}}


# ------------------------------------------------------------------ tuning + Sigma
@router.get("/tuning/suggestions")
async def tuning_suggestions(days: int = Query(90, ge=7, le=365), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from ..tuning import suggestions
    return await suggestions(s, days)


class TuningApply(BaseModel):
    type: str = Field(pattern=r"^(suppress_entity|raise_threshold)$")
    rule_key: str = Field(max_length=64)
    group_key: str | None = Field(None, max_length=512)
    param: str | None = Field(None, max_length=64)
    value: float | None = None
    hours: int | None = Field(None, ge=1, le=24 * 365)


@router.post("/tuning/apply")
async def tuning_apply(body: TuningApply, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    from ..db.models import Suppression
    from ..tuning import THRESHOLD_PARAM
    r = (await s.execute(select(AlertRule).where(AlertRule.key == body.rule_key))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "rule not found")
    if body.type == "suppress_entity":
        if not body.group_key:
            raise HTTPException(422, "group_key is required")
        until = datetime.now(timezone.utc) + timedelta(hours=body.hours) if body.hours else None
        s.add(Suppression(rule_key=r.key, group_key=body.group_key, until=until, reason="tuning suggestion (false positives only)",
                          created_by=user.username))
    else:
        if body.param != THRESHOLD_PARAM.get(r.key) or body.value is None or body.value < 0:
            raise HTTPException(422, "this parameter cannot be tuned here")
        r.params = {**(r.params or {}), body.param: int(body.value) if float(body.value).is_integer() else body.value}
    await s.commit()
    await audit(s, request, user.username, "tuning_apply", r.key, body.model_dump(exclude_none=True))
    return {"ok": True}


@router.post("/sigma/convert")
async def sigma_convert(body: dict, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from ..sigma import SigmaError, convert
    text = str(body.get("yaml", ""))
    if len(text) > 100_000:
        raise HTTPException(422, "rule too large")
    try:
        out = convert(text)
        compile_pipeline(out["query"], await load_watchlists(s, watchlist_names(out["query"])))
    except SigmaError as e:
        raise HTTPException(422, f"cannot convert: {e}")
    except PipelineError as e:
        raise HTTPException(422, f"converted query is invalid: {e}")
    return out


# ------------------------------------------------------------------ AI assistant
@router.get("/ai/status")
async def ai_status(_: User = Depends(current_user)):
    from .. import ai
    return ai.status()


@router.post("/ai/query")
async def ai_query(body: dict, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Plain-English question → pipeline query (only the question and the field catalogue leave the SIEM)."""
    from .. import ai
    q = str(body.get("question", ""))[:1000]
    names = [n for (n,) in (await s.execute(select(Watchlist.name))).all()]
    try:
        out = await ai.ask_query(q, names)
    except ai.AIError as e:
        raise HTTPException(422, str(e))
    await audit(s, request, user.username, "ai_query", q[:200], {"query": out["query"][:500]})
    return out


@router.post("/ai/incidents/{iid}/summary")
async def ai_incident_summary(iid: int, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from .. import ai
    inc = await s.get(Incident, iid)
    if not inc:
        raise HTTPException(404, "not found")
    alerts = (await s.execute(select(Alert).where(Alert.incident_id == iid).order_by(Alert.first_seen).limit(50))).scalars().all()
    comments = (await s.execute(select(IncidentComment).where(IncidentComment.incident_id == iid).order_by(IncidentComment.ts.desc())
                                .limit(20))).scalars().all()
    payload = {
        "incident": {"id": inc.id, "title": inc.title, "entity_type": inc.entity_type, "entity": inc.entity, "severity": inc.severity,
                     "status": inc.status, "tactics": inc.tactics, "techniques": inc.techniques, "asset_criticality": inc.asset_criticality,
                     "first_seen": iso(inc.first_seen), "last_seen": iso(inc.last_seen), "alert_count": inc.alert_count},
        "alerts": [{"rule": a.name, "severity": a.severity, "status": a.status, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
                    "events": a.event_count, "src_ip": a.src_ip, "dst_ip": a.dst_ip, "explanation": a.explanation, "mitre": a.mitre,
                    "evidence": {k: v for k, v in (a.evidence or {}).items() if k not in ("rows",)}} for a in alerts],
        "analyst_notes": [{"by": c.author, "at": iso(c.ts), "text": c.body[:1000]} for c in reversed(comments) if c.kind in ("comment", "evidence")],
        "tasks": [{"text": t["text"], "done": t.get("done")} for t in (inc.tasks or [])],
    }
    try:
        out = await ai.summarize_incident(payload)
    except ai.AIError as e:
        raise HTTPException(422, str(e))
    await audit(s, request, user.username, "ai_incident_summary", str(iid))
    return out
