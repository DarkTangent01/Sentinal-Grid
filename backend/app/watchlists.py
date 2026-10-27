"""Watchlists: named lookup lists for the pipeline query language, detections and automation."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Watchlist, WatchlistItem

KINDS = ("ip", "domain", "user", "string")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,63}$")
MAX_ITEMS = 50_000
DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$")


def normalize_value(kind: str, value: str) -> str:
    """Canonical form of one item; raises ValueError for values that do not fit the list kind."""
    v = (value or "").strip()
    if not v:
        raise ValueError("empty value")
    if len(v) > 255:
        raise ValueError("value longer than 255 characters")
    if kind == "ip":
        return str(ipaddress.ip_network(v, strict=False)) if "/" in v else str(ipaddress.ip_address(v))
    if kind == "domain":
        d = v.lower().lstrip("*.").rstrip(".")
        if not DOMAIN.match(d):
            raise ValueError(f"invalid domain '{v}'")
        return d
    if kind == "user":
        return v.lower()
    return v


def parse_items(kind: str, text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Lines of `value[,label]` (CSV-ish; a header row 'value,label' is skipped) → ([(value, label)], errors)."""
    out, errors, seen = [], [], set()
    for n, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, _, label = line.partition(",")
        if n == 1 and value.strip().lower() in ("value", "ip", "domain", "user", "indicator"):
            continue
        try:
            v = normalize_value(kind, value.strip().strip('"'))
        except ValueError as e:
            errors.append(f"line {n}: {e}")
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append((v, label.strip().strip('"')[:255]))
    return out, errors


async def load_watchlists(s: AsyncSession, names: set[str] | list[str]) -> dict[str, dict]:
    """{name: {kind, values, labels}} for the compiler; unknown names are left out (the compiler reports them)."""
    names = [n for n in names if n]
    if not names:
        return {}
    now = datetime.now(timezone.utc)
    lists = (await s.execute(select(Watchlist).where(Watchlist.name.in_(names)))).scalars().all()
    out = {}
    for w in lists:
        items = (await s.execute(select(WatchlistItem.value, WatchlistItem.label).where(
            WatchlistItem.watchlist_id == w.id, or_(WatchlistItem.expires_at.is_(None), WatchlistItem.expires_at > now))
            .limit(MAX_ITEMS))).all()
        out[w.name] = {"kind": "ip" if w.kind == "ip" else ("domain" if w.kind == "domain" else "string"),
                       "values": [v for v, _ in items], "labels": [l or "" for _, l in items]}
    return out


async def add_item(s: AsyncSession, w: Watchlist, value: str, label: str = "", added_by: str = "system",
                   expires_at: datetime | None = None) -> bool:
    """Idempotent add (used by automation). Returns True when a new item was created."""
    v = normalize_value(w.kind, value)
    exists = (await s.execute(select(WatchlistItem.id).where(WatchlistItem.watchlist_id == w.id, WatchlistItem.value == v))).first()
    if exists:
        return False
    s.add(WatchlistItem(watchlist_id=w.id, value=v, label=label[:255], added_by=added_by, expires_at=expires_at))
    w.updated_at = datetime.now(timezone.utc)
    return True
