"""Scheduled saved searches: count matching events and notify when a threshold is reached."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .analytics.filters import EventFilter, build_where, table
from .db.ch import ClickHouse
from .db.models import SavedSearch
from .notify import _link, enqueue

DUE = {"hourly": timedelta(hours=1), "daily": timedelta(days=1)}


async def count_matches(ch: ClickHouse, ql: str, range_: str) -> int:
    where, p = build_where(EventFilter(range=range_, ql=ql))
    r = await ch.aquery(f"SELECT count() AS n FROM {table()} WHERE {where}", p)
    return int(r[0]["n"]) if r else 0


async def run_due(s: AsyncSession, ch: ClickHouse, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    out = {}
    for ss in (await s.execute(select(SavedSearch).where(SavedSearch.schedule.in_(list(DUE))))).scalars().all():
        last = ss.last_run if ss.last_run is None or ss.last_run.tzinfo else ss.last_run.replace(tzinfo=timezone.utc)
        if last and now - last < DUE[ss.schedule]:
            continue
        try:
            n = await count_matches(ch, ss.query, ss.range)
        except ValueError as e:
            out[ss.name] = f"error: {e}"
            ss.last_run = now
            continue
        ss.last_run, ss.last_count = now, n
        if n >= max(1, ss.threshold):
            await enqueue(s, "search.threshold", {
                "title": f"Saved search '{ss.name}' matched {n:,} events", "text": f"Query: {ss.query} (last {ss.range}); threshold {ss.threshold}.",
                "fields": {"Matches": f"{n:,}", "Window": ss.range, "Owner": ss.owner}, "url": _link(f"/explorer?ql={ss.query}")},
                severity=ss.severity, dedupe_key=f"search:{ss.id}:{now:%Y%m%d%H}")
        out[ss.name] = n
    await s.commit()
    return out
