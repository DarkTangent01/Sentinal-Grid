"""Maintenance windows (Zabbix maintenance periods, LibreNMS alert schedules).

While a window is active, new alerts of the devices, sites and service checks it covers are held back (counted as
"maintenance" in the rule run, not created and not notified). Collection is never paused: graphs keep their data, and
an alert whose condition still holds when the window ends opens normally on the next evaluation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import NmsMaintenance


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown time zone: {name}")


def occurrence(m: NmsMaintenance, at: datetime) -> tuple[datetime, datetime] | None:
    """The window occurrence that contains `at` (UTC start, end), or None."""
    if not m.enabled:
        return None
    if m.kind == "once":
        a, b = _aware(m.starts_at), _aware(m.ends_at)
        return (a, b) if a and b and a <= at < b else None
    if not m.start_time or not m.weekdays:
        return None
    tz = zone(m.timezone)
    hh, mm = (int(x) for x in m.start_time.split(":"))
    local = at.astimezone(tz)
    dur = timedelta(minutes=max(1, int(m.duration_minutes or 0)))
    # a window can start the previous day(s) and run past midnight
    for back in range(0, 8):  # duration is capped at 7 days by the API
        day = (local - timedelta(days=back)).date()
        if day.weekday() not in m.weekdays:
            continue
        start = datetime(day.year, day.month, day.day, hh, mm, tzinfo=tz).astimezone(timezone.utc)
        if start <= at < start + dur:
            return start, start + dur
    return None


def covers(m: NmsMaintenance, *, switch_id: int | None = None, site: str | None = None, sites: list[str] | None = None,
           service_id: int | None = None) -> bool:
    if m.all_devices:
        return True
    if switch_id is not None and switch_id in (m.switch_ids or []):
        return True
    if service_id is not None and service_id in (m.service_ids or []):
        return True
    want = {x.strip().lower() for x in (m.sites or []) if x}
    have = {x.strip().lower() for x in ([site] if site else []) + list(sites or []) if x}
    return bool(want & have)


async def active(s: AsyncSession, at: datetime) -> list[NmsMaintenance]:
    rows = (await s.execute(select(NmsMaintenance).where(NmsMaintenance.enabled.is_(True)))).scalars().all()
    return [m for m in rows if occurrence(m, at)]


def detection_scope(d) -> dict:
    ev = d.evidence or {}
    return {"switch_id": ev.get("switch_id") if isinstance(ev.get("switch_id"), int) else None,
            "service_id": ev.get("service_id") if isinstance(ev.get("service_id"), int) else None,
            "site": ev.get("site") or None, "sites": list(d.sites or [])}


async def matcher(s: AsyncSession, at: datetime):
    """Callable detection → covering window (or None); None when no window is active."""
    wins = await active(s, at)
    if not wins:
        return None

    def match(d):
        sc = detection_scope(d)
        return next((m for m in wins if covers(m, **sc)), None)
    return match


def row(m: NmsMaintenance, now: datetime) -> dict:
    occ = occurrence(m, now)
    return {"id": m.id, "name": m.name, "reason": m.reason, "kind": m.kind, "starts_at": _iso(m.starts_at), "ends_at": _iso(m.ends_at),
            "weekdays": m.weekdays or [], "start_time": m.start_time, "duration_minutes": m.duration_minutes, "timezone": m.timezone,
            "all_devices": m.all_devices, "switch_ids": m.switch_ids or [], "sites": m.sites or [], "service_ids": m.service_ids or [],
            "enabled": m.enabled, "active": occ is not None, "active_until": _iso(occ[1]) if occ else None,
            "expired": m.kind == "once" and bool(m.ends_at) and _aware(m.ends_at) <= now, "created_by": m.created_by,
            "created_at": _iso(m.created_at)}


def _iso(v):
    v = _aware(v)
    return v.isoformat() if v else None
