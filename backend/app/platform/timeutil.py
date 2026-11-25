"""Time helpers for values read from ClickHouse (the embedded engine returns strings, the server returns datetimes,
sometimes timezone-naive)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def ch_time(v) -> datetime:
    """A ClickHouse timestamp (datetime or ISO text) as an aware UTC datetime."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


def to_utc(v) -> datetime | None:
    """Normalize ClickHouse timestamps to aware UTC; None for empty values and the zero date."""
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    else:
        text = str(v).strip().replace(" ", "T").replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return None if dt.year <= 1970 else dt


def hour_bounds(t0: datetime, t1: datetime) -> tuple[datetime, datetime]:
    """[h0, h1): the whole hours inside [t0, t1), read from policy_usage_hourly; [t0, h0) and [h1, t1) come from raw
    events. A window shorter than an hour has no whole hour: h0 = h1 = t1, so the raw part covers all of it."""
    h0 = t0.replace(minute=0, second=0, microsecond=0)
    h0 = h0 if h0 == t0 else h0 + timedelta(hours=1)
    h1 = t1.replace(minute=0, second=0, microsecond=0)
    return (h0, h1) if h0 < h1 else (t1, t1)
