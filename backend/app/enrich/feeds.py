"""Threat-intel feed management: built-in free feeds, custom feeds and a manual IOC list."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import TiFeed, TiIndicator
from ..netguard import request_guard
from .ti import parse_feed

from .connectors import CONNECTOR_KINDS, fetch as connector_fetch  # noqa: E402

log = logging.getLogger("ti")
MANUAL = "Manual IOCs"
DEFAULT_FEEDS = [
    {"name": "abuse.ch Feodo Tracker (botnet C2 IPs)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "kind": "ip", "category": "botnet_c2", "refresh_hours": 6},
    {"name": "Spamhaus DROP (hijacked netblocks)", "url": "https://www.spamhaus.org/drop/drop_v4.json",
     "kind": "cidr", "category": "hijacked_netblock", "refresh_hours": 24},
    {"name": "CERT Polska malicious domains", "url": "https://hole.cert.pl/domains/v2/domains.txt",
     "kind": "domain", "category": "phishing_malware", "refresh_hours": 6},
    {"name": "IPsum level 3 (aggregated malicious IPs)", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
     "kind": "ip", "category": "known_attacker", "refresh_hours": 24},
]
# built-in feeds whose upstream was withdrawn; existing installs get them disabled automatically
RETIRED = {"abuse.ch URLhaus (malware hosts)": "retired: abuse.ch withdrew the public hostfile download (HTTP 410)"}


def _now():
    return datetime.now(timezone.utc)


async def ensure_default_feeds(s: AsyncSession) -> None:
    feeds = list((await s.execute(select(TiFeed))).scalars())
    names = {f.name for f in feeds}
    for f in feeds:
        if f.builtin and f.name in RETIRED and f.enabled:
            f.enabled, f.last_status = False, RETIRED[f.name]
    for d in DEFAULT_FEEDS:
        if d["name"] not in names:
            s.add(TiFeed(builtin=True, enabled=True, **d))
    if MANUAL not in names:
        s.add(TiFeed(name=MANUAL, url="", kind="manual", category="analyst_ioc", builtin=True, enabled=True, refresh_hours=0,
                     last_status="manual list"))
    await s.commit()


async def replace_indicators(s: AsyncSession, feed: TiFeed, items: list) -> int:
    """Replace a feed's indicators with a fresh fetch. `items`: (indicator, type) pairs or connector rows (dicts).
    Kept across the refresh: when each indicator was first added here, and analyst false-positive verdicts."""
    keep = {r.indicator: (r.added_at, r.false_positive, r.fp_by, r.note) for r in
            (await s.execute(select(TiIndicator).where(TiIndicator.feed_id == feed.id))).scalars()}
    await s.execute(delete(TiIndicator).where(TiIndicator.feed_id == feed.id))
    now = _now()
    expiry = now + timedelta(days=feed.expire_days) if (feed.expire_days or 0) > 0 else None
    rows = []
    for it in items:
        d = it if isinstance(it, dict) else {"indicator": it[0], "type": it[1]}
        old = keep.get(d["indicator"][:255])
        rows.append({"feed_id": feed.id, "indicator": d["indicator"][:255], "type": d["type"], "note": old[3] if old else "",
                     "added_at": old[0] if old else now, "confidence": d.get("confidence"), "threat": d.get("threat", "") or "",
                     "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen"), "expires_at": d.get("expires_at") or expiry,
                     "false_positive": bool(old[1]) if old else False, "fp_by": old[2] if old else ""})
    for k in range(0, len(rows), 5000):  # bulk executemany; feeds can hold 100k+ indicators
        await s.execute(insert(TiIndicator), rows[k:k + 5000])
    feed.indicator_count = len(items)
    return len(items)


async def fetch_feed(s: AsyncSession, feed: TiFeed, transport: httpx.AsyncBaseTransport | None = None) -> str:
    """Download and parse one feed. Data only: content is parsed as text, never executed."""
    if feed.kind == "manual" or not feed.url:
        return "manual"
    st = get_settings()
    feed.last_fetch = _now()
    try:
        if not feed.url.lower().startswith("https://"):
            raise ValueError("only https:// feeds are allowed")
        headers = {"User-Agent": "Sentinel-Grid/1.0 (threat-intel feed fetch)"}
        if feed.auth_ciphertext and feed.auth_header:   # the key is decrypted here and sent only to the feed's own host
            from ..security import TokenCipher
            headers[feed.auth_header] = TokenCipher().decrypt(feed.auth_ciphertext)
        if feed.kind in CONNECTOR_KINDS:
            async with httpx.AsyncClient(timeout=60, follow_redirects=False, transport=transport, headers=headers,
                                         event_hooks={"request": [request_guard(("https",))]}) as c:
                rows = await connector_fetch(feed.kind, feed.url, c, st.ti_fetch_max_bytes)
            if not rows:
                raise ValueError("the source returned no usable indicators")
            n = await replace_indicators(s, feed, rows)
            feed.last_success = _now()
            feed.last_status = f"ok: {n} indicators"
            await s.commit()
            return feed.last_status
        # redirects are followed (feeds move to CDNs), but every hop must stay https and pass the SSRF guard
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, max_redirects=5, transport=transport,
                                     event_hooks={"request": [request_guard(("https",))]},
                                     headers=headers) as c:
            async with c.stream("GET", feed.url) as r:
                r.raise_for_status()
                chunks, size = [], 0
                async for ch in r.aiter_bytes():
                    size += len(ch)
                    if size > st.ti_fetch_max_bytes:
                        raise ValueError(f"feed larger than {st.ti_fetch_max_bytes} bytes")
                    chunks.append(ch)
        items = parse_feed(b"".join(chunks).decode("utf-8", "replace"), feed.kind)
        if not items:
            raise ValueError("no indicators parsed (format changed?)")
        n = await replace_indicators(s, feed, items)
        feed.last_success = _now()
        feed.last_status = f"ok: {n} indicators"
    except Exception as e:  # keep the previous indicators when a refresh fails
        feed.last_status = f"error: {type(e).__name__}: {e}"[:500]
        log.warning("feed %s failed: %s", feed.name, e)
    await s.commit()
    return feed.last_status


async def refresh_due_feeds(s: AsyncSession) -> dict:
    out = {}
    for f in (await s.execute(select(TiFeed).where(TiFeed.enabled.is_(True), TiFeed.kind != "manual"))).scalars().all():
        due = f.last_fetch is None or (f.last_fetch if f.last_fetch.tzinfo else f.last_fetch.replace(tzinfo=timezone.utc)) \
            < _now() - timedelta(hours=max(1, f.refresh_hours))
        if due:
            out[f.name] = await fetch_feed(s, f)
    return out
