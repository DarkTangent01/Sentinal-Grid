"""Behaviour baselines: what is normal for each internal host and VLAN, by hour of day, and what departs from it.

Source: the hourly conversation rollup (flows_conv_hourly). For a host (or VLAN) and metric — bytes sent (upload),
bytes received, distinct peers — the baseline of an hour of the day is the median and the median absolute deviation
(MAD) of the same hour over the previous BASELINE_DAYS days, counting a day without traffic as zero (a host that is
normally silent at 03:00 has a baseline of zero). An observation departs from it when
    value ≥ median + k × max(MAD, 10 % of median, floor)   and   value ≥ factor × max(median, floor)   and   value ≥ min
Learning: no verdicts until the rollup holds LEARNING_DAYS of history. Figures from sampled telemetry are estimates.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import median

BASELINE_DAYS = 14
LEARNING_DAYS = 5
METRICS = {"bytes_out": "upload", "bytes_in": "download", "peers": "distinct peers"}


def robust(values: list[float]) -> tuple[float, float]:
    """(median, MAD) of a list (empty → 0, 0)."""
    if not values:
        return 0.0, 0.0
    m = median(values)
    return float(m), float(median([abs(v - m) for v in values]))


def departs(value: float, base: list[float], *, k: float, factor: float, floor: float, minimum: float) -> tuple[bool, dict]:
    m, mad = robust(base)
    spread = max(mad, 0.1 * m, floor)
    upper = m + k * spread
    ok = value >= minimum and value >= upper and value >= factor * max(m, floor)
    return ok, {"median": m, "mad": mad, "expected_max": upper, "factor": round(value / max(m, floor), 1)}


def _hour(t: datetime) -> datetime:
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return t.replace(minute=0, second=0, microsecond=0)


async def history_start(ch) -> datetime | None:
    r = await ch.aquery("SELECT min(hour) AS h, count() AS n FROM flows_conv_hourly")
    if not r or not int(r[0]["n"]):
        return None
    h = r[0]["h"]
    h = h if isinstance(h, datetime) else datetime.fromisoformat(str(h))
    return h if h.tzinfo else h.replace(tzinfo=timezone.utc)


def _key_expr(scope: str) -> str:
    # the host on the internal side is the conversation's client (the side that is not the server)
    return {"host": "if(server_is_dst = 1, src_ip, dst_ip)", "vlan": "toString(vlan)"}[scope]


async def hourly(ch, scope: str, keys: list[str] | None, start: datetime, end: datetime) -> dict[str, dict[datetime, dict]]:
    """key → hour → {bytes_out, bytes_in, peers} (bytes_out: sent by the internal host)."""
    k = _key_expr(scope)
    sent = "sumIf(bytes, if(server_is_dst = 1, 1, 0) = 1)" if scope == "host" else "sum(bytes)"
    recv = "sumIf(bytes, server_is_dst = 0)" if scope == "host" else "toUInt64(0)"
    peer = "uniqExact(if(server_is_dst = 1, dst_ip, src_ip))" if scope == "host" else "uniqExact(src_ip)"
    where = "hour >= {a:DateTime64(3)} AND hour < {b:DateTime64(3)}"
    p: dict = {"a": start, "b": end}
    if keys is not None:
        where += f" AND {k} IN {{keys:Array(String)}}"
        p["keys"] = keys or ["-"]
    if scope == "vlan":
        where += " AND vlan != 0"
    rows = await ch.aquery(f"SELECT {k} AS key, hour, {sent} AS bo, {recv} AS bi, {peer} AS peers FROM flows_conv_hourly WHERE {where} "
                           "GROUP BY key, hour LIMIT 2000000", p)
    out: dict[str, dict[datetime, dict]] = {}
    for r in rows:
        h = r["hour"] if isinstance(r["hour"], datetime) else datetime.fromisoformat(str(r["hour"]))
        h = h if h.tzinfo else h.replace(tzinfo=timezone.utc)
        out.setdefault(r["key"], {})[h] = {"bytes_out": int(r["bo"]), "bytes_in": int(r["bi"]), "peers": int(r["peers"])}
    return out


def same_hour_history(series: dict[datetime, dict], hour: datetime, metric: str, days: int, since: datetime) -> list[float]:
    """The metric at the same hour of day on each of the previous `days` days that the rollup covers (zeros included)."""
    out = []
    for d in range(1, days + 1):
        h = hour - timedelta(days=d)
        if h < since:
            break
        out.append(float((series.get(h) or {}).get(metric, 0)))
    return out


async def profile(ch, ip: str, now: datetime | None = None, hours: int = 48) -> dict:
    """The last `hours` hours of one host with the expected band for each hour (median and median + 3 × spread)."""
    now = _hour(now or datetime.now(timezone.utc))
    start = await history_start(ch)
    if start is None:
        return {"ip": ip, "learning": True, "points": []}
    data = (await hourly(ch, "host", [ip], now - timedelta(days=BASELINE_DAYS, hours=hours), now + timedelta(hours=1))).get(ip, {})
    pts = []
    for i in range(hours, -1, -1):
        h = now - timedelta(hours=i)
        cur = data.get(h) or {}
        base = same_hour_history(data, h, "bytes_out", BASELINE_DAYS, start)
        m, mad = robust(base)
        pts.append({"t": h.isoformat(), "bytes_out": cur.get("bytes_out", 0), "bytes_in": cur.get("bytes_in", 0), "peers": cur.get("peers", 0),
                    "expected": m, "expected_max": m + 3 * max(mad, 0.1 * m), "samples": len(base)})
    return {"ip": ip, "learning": (now - start) < timedelta(days=LEARNING_DAYS), "history_days": max(0, (now - start).days), "points": pts}
