"""HTTP ingestion and ingestion health.

POST /api/ingest/{source_id}   Authorization: Bearer <token of that log source>
    Body: newline-separated records (JSON lines, CEF / LEEF / syslog lines, Zeek JSON), or a JSON array of objects /
    strings. Each record goes through the same parser as that source's syslog (app/ingest/generic.py) and into the same
    `events` table. The response is sent after ClickHouse accepted the batch, so a 200 is an acknowledgement: on any
    other status the sender must retry the same batch (event ids are derived from source + record, so a retry never
    duplicates). Limits: 2,000 records and 1 MB per request (the web tier's body limit), 120 requests per minute per source.

GET /api/log-sources/health    per-source ingestion health: volume, lag, last event, and everything that was not stored
    as an event (rejected, duplicate, bad timestamp) with the reason and a sample; senders nobody registered.
POST /api/log-sources/parse-test   administrators: how a pasted line is parsed and normalized (nothing is stored).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.ch_schema import EVENT_COLUMNS
from ..db.models import Firewall, IngestStat, LogSource, User
from ..db.pg import get_session
from ..ingest import generic
from ..ingest.pipeline import _write_rejects, persist_stats
from ..ingest.schema_map import to_ecs
from .deps import audit, ch_dep, client_ip, current_user, iso, limiter, require_admin

router = APIRouter(prefix="/api", tags=["ingest"])
MAX_RECORDS, MAX_BYTES, PER_MINUTE = 2000, 1_000_000, 120
_enricher = None


async def _enrich():
    """GeoIP / threat-intel enrichment, loaded on first use (the indicator set is refreshed at most every 5 minutes)."""
    global _enricher
    if _enricher is None:
        from ..enrich.enricher import Enricher
        _enricher = Enricher()
    try:
        await _enricher.refresh_ti()
    except Exception:
        pass
    return _enricher


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def split_records(body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="replace").strip()
    if text.startswith("["):
        try:
            arr = json.loads(text)
        except ValueError:
            arr = None
        if isinstance(arr, list):
            return [x if isinstance(x, str) else json.dumps(x, separators=(",", ":")) for x in arr if x not in (None, "")]
    return [ln for ln in (x.strip() for x in text.splitlines()) if ln]


@router.post("/ingest/{sid}")
async def http_ingest(sid: int, request: Request, s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    auth = request.headers.get("authorization") or ""
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    src = await s.get(LogSource, sid)
    # one answer for "no such source", "HTTP ingest off" and "wrong token": nothing to enumerate
    if not token or src is None or not src.token_hash or not hmac.compare_digest(_hash(token), src.token_hash):
        raise HTTPException(401, "invalid source or token")
    if not src.enabled:
        raise HTTPException(403, "log source is disabled")
    if not limiter.check(f"ingest:{sid}", PER_MINUTE):
        raise HTTPException(429, "rate limit exceeded: retry the same batch later")
    body = await request.body()
    if len(body) > MAX_BYTES:
        raise HTTPException(413, f"batch larger than {MAX_BYTES} bytes: split it")
    records = split_records(body)
    if len(records) > MAX_RECORDS:
        raise HTTPException(413, f"more than {MAX_RECORDS} records: split the batch")
    sender = client_ip(request)
    meta = {"id": src.id, "name": src.name, "kind": src.kind, "site": src.site}
    enricher = await _enrich()
    events, seen, rejects = [], set(), {}
    last = None

    def reject(reason: str, raw: str | None):
        r = rejects.setdefault((reason, sender, src.name, "http"), {"count": 0, "sample": ""})
        r["count"] += 1
        if raw and not r["sample"]:
            from ..ingest.netdev import redact
            r["sample"] = redact(raw[:2000])
    for rec in records:
        try:
            ev = generic.parse(meta, rec)
        except Exception:
            ev = None
        if ev is None:
            reject("parse_error", rec)
            continue
        if ev["event_id"] in seen:
            reject("duplicate", None)
            continue
        seen.add(ev["event_id"])
        if ev["parser_version"].endswith("+bad-ts"):
            reject("bad_timestamp", rec)
        ev["source"] = "http"
        enricher.apply(ev)
        events.append(ev)
        last = ev["event_time"] if last is None or ev["event_time"] > last else last
    if events:
        # Idempotent retry: records without a usable timestamp of their own take the receive time, so the table's own
        # dedupe (same time + id) would not catch a re-sent batch. Ids of this source seen in the last day are skipped.
        try:
            known = {r["event_id"] for r in await ch.aquery(
                "SELECT event_id FROM events WHERE firewall_id = {f:UInt32} AND event_time >= now() - INTERVAL 1 DAY AND event_id IN {ids:Array(String)}",
                {"f": generic.SOURCE_ID_BASE + src.id, "ids": [e["event_id"] for e in events]})}
        except Exception:
            raise HTTPException(503, "event store unavailable: retry the same batch")
        if known:
            for e in events:
                if e["event_id"] in known:
                    reject("duplicate", None)
            events = [e for e in events if e["event_id"] not in known]
    if events:
        try:
            await ch.ainsert("events", events, EVENT_COLUMNS)
        except Exception:
            # not stored: the sender keeps the batch and retries (nothing was acknowledged)
            raise HTTPException(503, "event store unavailable: retry the same batch")
        await persist_stats({(generic.SOURCE_ID_BASE + src.id, "http"): {"events": len(events), "errors": 0, "last_event": last, "last_error": None}})
    if rejects:
        try:
            await _write_rejects(ch, rejects)
        except Exception:
            pass
    return {"received": len(records), "accepted": len(events), "duplicates": sum(r["count"] for k, r in rejects.items() if k[0] == "duplicate"),
            "rejected": sum(r["count"] for k, r in rejects.items() if k[0] == "parse_error"),
            "bad_timestamp": sum(r["count"] for k, r in rejects.items() if k[0] == "bad_timestamp")}


@router.post("/log-sources/{sid}/token")
async def create_token(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    src = await s.get(LogSource, sid)
    if not src:
        raise HTTPException(404, "not found")
    token = "sgi_" + secrets.token_urlsafe(32)
    src.token_hash, src.token_hint, src.token_created_at = _hash(token), token[-4:], datetime.now(timezone.utc)
    await s.commit()
    await audit(s, request, user.username, "log_source_token_create", src.name)
    # shown once: only the hash is stored
    return {"token": token, "hint": src.token_hint, "url": f"/api/ingest/{src.id}"}


@router.delete("/log-sources/{sid}/token")
async def revoke_token(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    src = await s.get(LogSource, sid)
    if not src:
        raise HTTPException(404, "not found")
    src.token_hash, src.token_hint, src.token_created_at = None, "", None
    await s.commit()
    await audit(s, request, user.username, "log_source_token_revoke", src.name)
    return {"ok": True}


class ParseTestIn(BaseModel):
    kind: str = Field(pattern=r"^(windows|cef|netdev|syslog|zeek|json|leef|linux)$")
    line: str = Field(min_length=1, max_length=20000)


@router.post("/log-sources/parse-test")
async def parse_test(body: ParseTestIn, _: User = Depends(require_admin)):
    ev = generic.parse({"id": 0, "name": "parse-test", "kind": body.kind, "site": ""}, body.line)
    if ev is None:
        return {"parsed": False}
    shown = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in ev.items() if v not in ("", None, 0, []) and k not in ("raw", "ingest_time")}
    return {"parsed": True, "fell_back_to_plain": ev["event_type"] == "syslog" and body.kind != "syslog", "parser_version": ev["parser_version"],
            "normalized": shown, "ecs": to_ecs(ev)}


def _aware(v):
    if isinstance(v, str):   # the embedded engine returns DateTime as text
        try:
            v = datetime.fromisoformat(v.replace(" ", "T"))
        except ValueError:
            return None
    return v.replace(tzinfo=timezone.utc) if v is not None and v.tzinfo is None else v


@router.get("/log-sources/health")
async def health(_: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    now = datetime.now(timezone.utc)
    fws = (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars().all()
    srcs = (await s.execute(select(LogSource))).scalars().all()
    stats = {}
    for st in (await s.execute(select(IngestStat))).scalars():
        cur = stats.get(st.firewall_id)
        if cur is None or (_aware(st.last_ingest_time) or datetime.min.replace(tzinfo=timezone.utc)) > (_aware(cur.last_ingest_time) or datetime.min.replace(tzinfo=timezone.utc)):
            stats[st.firewall_id] = st
    vol = {int(r["firewall_id"]): r for r in await ch.aquery(
        "SELECT firewall_id, sumIf(events, minute >= now() - INTERVAL 1 HOUR) AS h1, sum(events) AS h24, max(minute) AS last "
        "FROM events_minute WHERE minute >= now() - INTERVAL 1 DAY GROUP BY firewall_id")}
    lag = {int(r["firewall_id"]): r for r in await ch.aquery(
        "SELECT firewall_id, quantile(0.5)(l) AS p50, quantile(0.95)(l) AS p95 FROM (SELECT firewall_id, "
        "greatest(0, dateDiff('millisecond', event_time, ingest_time)) / 1000 AS l FROM events WHERE ingest_time >= now() - INTERVAL 15 MINUTE "
        "AND event_time >= now() - INTERVAL 1 DAY AND parser_version NOT LIKE '%-ts') GROUP BY firewall_id")}
    rej = await ch.aquery("SELECT source_name, sender, reason, sum(count) AS n, max(ts) AS last, argMax(sample, ts) AS sample FROM ingest_rejects "
                          "WHERE ts >= now() - INTERVAL 1 DAY GROUP BY source_name, sender, reason ORDER BY n DESC LIMIT 2000")
    by_name: dict[str, dict] = {}
    for r in rej:
        if r["source_name"]:
            d = by_name.setdefault(r["source_name"], {})
            d[r["reason"]] = d.get(r["reason"], 0) + int(r["n"])

    def row(name, kind, fid, enabled, last_event, site, extra=None):
        v, lg, rj = vol.get(fid), lag.get(fid), by_name.get(name, {})
        last = _aware(last_event)
        silent_s = (now - last).total_seconds() if last else None
        status = "disabled" if not enabled else "never" if last is None and not v else "silent" if silent_s is not None and silent_s > 3600 and not (v and int(v["h1"])) \
            else "degraded" if rj.get("parse_error") or rj.get("bad_timestamp") or rj.get("buffer_full") else "ok"
        return {"name": name, "kind": kind, "firewall_id": fid, "site": site, "enabled": enabled, "status": status, "last_event_at": iso(last),
                "events_1h": int(v["h1"]) if v else 0, "events_24h": int(v["h24"]) if v else 0,
                "lag_p50_s": round(float(lg["p50"]), 1) if lg else None, "lag_p95_s": round(float(lg["p95"]), 1) if lg else None,
                "duplicates_24h": rj.get("duplicate", 0), "parse_errors_24h": rj.get("parse_error", 0), "bad_timestamps_24h": rj.get("bad_timestamp", 0),
                "dropped_24h": rj.get("buffer_full", 0), "source_mismatch_24h": rj.get("source_mismatch", 0), **(extra or {})}
    sources = [row(f.name, f.vendor or "fortinet", f.id, f.enabled, getattr(stats.get(f.id), "last_event_time", None), f.site) for f in fws]
    sources += [row(x.name, x.kind, generic.SOURCE_ID_BASE + x.id, x.enabled, x.last_event_at, x.site, {"http_ingest": bool(x.token_hash)}) for x in srcs]
    unknown = [{"sender": r["sender"], "claims_to_be": r["source_name"], "reason": r["reason"], "count": int(r["n"]), "last_seen": iso(_aware(r["last"])), "sample": r["sample"][:500]}
               for r in rej if r["reason"] in ("unknown_device", "source_mismatch")][:100]
    totals: dict[str, int] = {}
    for r in rej:
        totals[r["reason"]] = totals.get(r["reason"], 0) + int(r["n"])
    timeline = await ch.aquery("SELECT toStartOfHour(ts) AS t, reason, sum(count) AS n FROM ingest_rejects WHERE ts >= now() - INTERVAL 1 DAY GROUP BY t, reason ORDER BY t")
    stored = await ch.aquery("SELECT toStartOfHour(minute) AS t, sum(events) AS n FROM events_minute WHERE minute >= now() - INTERVAL 1 DAY GROUP BY t ORDER BY t")
    samples = [{"source": r["source_name"], "sender": r["sender"], "reason": r["reason"], "count": int(r["n"]), "last_seen": iso(_aware(r["last"])), "sample": r["sample"][:500]}
               for r in rej if r["reason"] in ("parse_error", "bad_timestamp", "buffer_full") and r["sample"]][:50]
    return {"sources": sorted(sources, key=lambda x: ({"silent": 0, "degraded": 1, "never": 2, "ok": 3, "disabled": 4}[x["status"]], x["name"].lower())),
            "not_stored_24h": totals, "stored_24h": sum(int(r["n"]) for r in stored), "unknown_senders": unknown, "samples": samples,
            "timeline": {"stored": [{"t": iso(_aware(r["t"])), "n": int(r["n"])} for r in stored],
                         "not_stored": [{"t": iso(_aware(r["t"])), "reason": r["reason"], "n": int(r["n"])} for r in timeline]},
            "reasons": {"duplicate": "same event received again (not stored twice)", "unknown_device": "sender is not a registered firewall or log source",
                        "source_mismatch": "the message names a firewall, but the sender is not one of its addresses", "parse_error": "the line could not be parsed",
                        "bad_timestamp": "device clock far in the future or invalid: stored with the receive time", "buffer_full": "dropped: UDP arrived faster than the store accepted"}}
