"""Custom detections (analytics rules): a scheduled pipeline query → alerts.

Stored as alert_rules rows with key `cq_<n>` so they share suppression, grouping, incident correlation, notifications
and rule-effectiveness stats with the built-in rules. params:
    query             pipeline query
    lookback_minutes  window the query runs over (default 60)
    interval_minutes  how often it runs (default 5)
    trigger_op        gt | ge | eq | ne | lt | le          compared against the number of result rows
    trigger_count     threshold (default 0, i.e. "any result")
    grouping          per_row (one alert per result row) | single (one alert for the whole result)
    entity_fields     fields that identify a row's entity (default: src_ip/user/... or every text column)
    explanation       template, e.g. "{src_ip} contacted {dsts} hosts"
"""
from __future__ import annotations

import re
import string
from datetime import datetime, timedelta, timezone

from ..analytics.filters import EventFilter
from ..analytics.pipeline import run_pipeline, watchlist_names
from ..watchlists import load_watchlists
from .engine import Detection, _dt

OPS = {"gt": lambda n, t: n > t, "ge": lambda n, t: n >= t, "eq": lambda n, t: n == t, "ne": lambda n, t: n != t,
       "lt": lambda n, t: n < t, "le": lambda n, t: n <= t}
ENTITY_HINTS = ("src_ip", "src", "user", "dst_ip", "dst", "domain", "hostname", "dns_qname", "firewall_name")
SRC_KEYS, DST_KEYS = ("src_ip", "src", "client", "source_ip"), ("dst_ip", "dst", "destination", "dest_ip")
IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")
DEFAULTS = {"lookback_minutes": 60, "interval_minutes": 5, "trigger_op": "gt", "trigger_count": 0, "grouping": "per_row",
            "entity_fields": [], "explanation": ""}


class _SafeFormat(string.Formatter):
    """str.format with only plain {name} lookups: no attribute/index access, missing keys render as '?'."""
    def get_field(self, field_name, args, kwargs):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field_name):
            return "?", field_name
        return kwargs.get(field_name, "?"), field_name

    def format_field(self, value, format_spec):
        return super().format_field(value, "")


def render_explanation(template: str, row: dict) -> str:
    try:
        return _SafeFormat().format(template[:500], **{k: (", ".join(map(str, v)) if isinstance(v, list) else v) for k, v in row.items()})
    except (ValueError, IndexError):
        return template[:500]


def _scalar_text(v) -> bool:
    return isinstance(v, str) and v != ""


def entity_key(row: dict, fields: list[str]) -> str:
    keys = [f for f in fields if f in row] or [f for f in ENTITY_HINTS if f in row] or \
        [k for k, v in row.items() if k not in ("_time", "event_time") and _scalar_text(v)]
    return "|".join(str(row.get(k, "")) for k in keys)[:500] or "result"


def _ip(row: dict, keys) -> str | None:
    for k in keys:
        v = row.get(k)
        if isinstance(v, str) and v and IP_RE.match(v):
            return v
    return None


def _time(row: dict, default: datetime) -> datetime:
    for k in ("last_seen", "latest_event_time", "_time", "event_time", "first_seen"):
        if row.get(k):
            try:
                return _dt(row[k])
            except ValueError:
                continue
    return default


async def evaluate(ch, s, now: datetime, params: dict, *, name: str = "custom detection") -> tuple[list[Detection], dict]:
    p = {**DEFAULTS, **(params or {})}
    lookback = max(1, min(int(p["lookback_minutes"]), 60 * 24 * 14))
    t0 = now - timedelta(minutes=lookback)
    wl = await load_watchlists(s, watchlist_names(p["query"]))
    res = await run_pipeline(ch, p["query"], EventFilter(start=t0, end=now, range=None), wl, max_rows=1000)
    rows = res["rows"]
    n = len(rows)
    op = OPS.get(p["trigger_op"], OPS["gt"])
    fired = op(n, int(p["trigger_count"]))
    info = {"rows": n, "truncated": res["truncated"], "fired": fired, "kind": res["kind"], "elapsed_ms": res["elapsed_ms"]}
    if not fired:
        return [], info
    search = res.get("search") or ""
    base_filter = {"ql": search} if search else {}
    win = {"window_start": t0.isoformat(), "window_end": now.isoformat(), "query": p["query"]}
    if p["grouping"] == "single" or res["kind"] == "events":
        sample = rows[:20]
        src = _ip(rows[0], SRC_KEYS) if n == 1 else None
        expl = render_explanation(p["explanation"], {**(rows[0] if rows else {}), "count": n}) if p["explanation"] else \
            f"{name}: query returned {n}{'+' if res['truncated'] else ''} result(s) in the last {lookback} min."
        times = [_time(r, now) for r in rows] or [now]
        return [Detection(group_key="all", count=n, first_seen=min(times), last_seen=max(times), explanation=expl, src_ip=src,
                          evidence={**win, "rows": sample, "result_count": n}, event_filter=base_filter)], info
    dets = []
    for row in rows[:50]:
        key = entity_key(row, list(p["entity_fields"] or []))
        src, dst = _ip(row, SRC_KEYS), _ip(row, DST_KEYS)
        cnt = row.get("count")
        cnt = int(cnt) if isinstance(cnt, (int, float)) else 1
        expl = render_explanation(p["explanation"], row) if p["explanation"] else \
            f"{name}: " + ", ".join(f"{k}={v}" for k, v in list(row.items())[:6])
        ql = " ".join(x for x in (search, f"src_ip:{src}" if src else "") if x)
        fw = row.get("firewall_id")
        dets.append(Detection(group_key=key, count=cnt, first_seen=_dt(row["first_seen"]) if row.get("first_seen") else t0,
                              last_seen=_time(row, now), explanation=expl[:2000], src_ip=src, dst_ip=dst,
                              firewall_ids=[int(fw)] if isinstance(fw, int) else [], evidence={**win, "row": row},
                              event_filter={"ql": ql} if ql else {}))
    return dets, info
