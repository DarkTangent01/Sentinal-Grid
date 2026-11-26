"""Interface bandwidth history: series at the right resolution, period statistics, period comparison and retention.

Storage (ClickHouse; all UTC):
  switch_if_samples   one row per interface per poll (60 s by default): rates already computed from counter deltas by
                      rates.interface_rates (resets / wraps / gaps refused or flagged) — kept `raw_days` (default 35)
  switch_if_5m        5-minute rollup (avg / min / max, bits transferred, errors) — kept `five_min_days` (default 90)
  switch_if_hourly    hourly rollup — kept `hourly_days` (default 400)

Nothing here invents a value: a bucket without a valid sample is absent (a gap in the chart), statistics count only
rated samples, and every figure says which table and resolution it came from.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import MonitoringSetting
from .rates import GAP, RESET
from .service import _f, _iso, bucket

RETENTION_KEY = "interface_retention"
RETENTION_DEFAULTS = {"raw_days": 35, "five_min_days": 90, "hourly_days": 400}
RETENTION_LIMITS = {"raw_days": (1, 120), "five_min_days": (7, 730), "hourly_days": (30, 3650)}
TABLES = {"raw_days": ("switch_if_samples", "ts"), "five_min_days": ("switch_if_5m", "bucket"), "hourly_days": ("switch_if_hourly", "hour")}
RAW_MAX = 2 * 86400            # longer spans than this read a rollup
FIVE_MAX = 90 * 86400


async def retention(s: AsyncSession) -> dict:
    row = await s.get(MonitoringSetting, RETENTION_KEY)
    return {**RETENTION_DEFAULTS, **((row.value or {}) if row else {})}


def validate_retention(v: dict) -> dict:
    out = {**RETENTION_DEFAULTS, **{k: int(x) for k, x in v.items() if k in RETENTION_DEFAULTS}}
    for k, (lo, hi) in RETENTION_LIMITS.items():
        if not lo <= out[k] <= hi:
            raise ValueError(f"{k} must be {lo}-{hi} days")
    if not out["raw_days"] <= out["five_min_days"] <= out["hourly_days"]:
        raise ValueError("retention must not shrink with coarser resolution: raw ≤ 5-minute ≤ hourly")
    return out


async def set_retention(s: AsyncSession, ch, value: dict, user: str) -> dict:
    """Store and apply (ALTER TABLE … MODIFY TTL). Shortening drops older data at the next merge."""
    v = validate_retention(value)
    for k, (table, col) in TABLES.items():
        await ch.acommand(f"ALTER TABLE {table} MODIFY TTL {col} + INTERVAL {int(v[k])} DAY")
    row = await s.get(MonitoringSetting, RETENTION_KEY)
    if row is None:
        row = MonitoringSetting(key=RETENTION_KEY)
        s.add(row)
    row.value, row.updated_by, row.updated_at = v, user, datetime.now(timezone.utc)
    await s.commit()
    return v


def source_for(t0: datetime, t1: datetime, ret: dict, now: datetime | None = None) -> str:
    """The finest table that covers the whole window."""
    now = now or datetime.now(timezone.utc)
    span, age = (t1 - t0).total_seconds(), (now - t0).total_seconds()
    if span <= RAW_MAX and age <= ret["raw_days"] * 86400:
        return "raw"
    if span <= FIVE_MAX and age <= ret["five_min_days"] * 86400:
        return "5m"
    return "hourly"


async def series(ch, sid: int, ifx: int, t0: datetime, t1: datetime, ret: dict) -> dict:
    src = source_for(t0, t1, ret)
    p = {"sid": sid, "ifx": ifx, "t0": t0, "t1": t1, "reset": RESET, "gap": GAP}
    if src == "raw":
        b = bucket(t0, t1)
        rows = await ch.aquery(
            f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avg(rx_bps) AS rx, avg(tx_bps) AS tx, max(rx_bps) AS rx_max, max(tx_bps) AS tx_max, "
            "max(rx_util) AS rx_util, max(tx_util) AS tx_util, sum(ifNull(in_errors, 0) + ifNull(out_errors, 0)) AS errors, "
            "sum(ifNull(in_discards, 0) + ifNull(out_discards, 0)) AS discards, min(oper) AS oper_min, max(bitAnd(flags, {gap:UInt8})) AS gap "
            "FROM switch_if_samples WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} "
            "AND bitAnd(flags, {reset:UInt8}) = 0 GROUP BY t ORDER BY t", p)
    elif src == "5m":
        b = max(300, bucket(t0, t1, 300))
        rows = await ch.aquery(
            f"SELECT toStartOfInterval(bucket, INTERVAL {b} SECOND) AS t, if(sum(rated) > 0, sum(rx_bps_sum) / sum(rated), NULL) AS rx, "
            "if(sum(rated) > 0, sum(tx_bps_sum) / sum(rated), NULL) AS tx, max(rx_bps_max) AS rx_max, max(tx_bps_max) AS tx_max, "
            "max(rx_util_max) AS rx_util, max(tx_util_max) AS tx_util, sum(in_errors + out_errors) AS errors, sum(in_discards + out_discards) AS discards, "
            "if(sum(down_samples) > 0, 0, 1) AS oper_min, 0 AS gap FROM switch_if_5m "
            "WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} AND bucket >= {t0:DateTime64(3)} AND bucket < {t1:DateTime64(3)} "
            "GROUP BY t ORDER BY t", p)
    else:
        b = max(3600, bucket(t0, t1, 3600))
        rows = await ch.aquery(
            f"SELECT toStartOfInterval(hour, INTERVAL {b} SECOND) AS t, if(sum(rated) > 0, sum(rx_bps_sum) / sum(rated), NULL) AS rx, "
            "if(sum(rated) > 0, sum(tx_bps_sum) / sum(rated), NULL) AS tx, if(sum(rated) > 0, max(rx_bps_max), NULL) AS rx_max, "
            "if(sum(rated) > 0, max(tx_bps_max), NULL) AS tx_max, max(rx_util_max) AS rx_util, max(tx_util_max) AS tx_util, "
            "sum(in_errors + out_errors) AS errors, sum(in_discards + out_discards) AS discards, if(sum(down_samples) > 0, 0, 1) AS oper_min, 0 AS gap "
            "FROM switch_if_hourly WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} AND hour >= toStartOfHour({t0:DateTime64(3)}) "
            "AND hour < {t1:DateTime64(3)} GROUP BY t ORDER BY t", p)
    pts = [{"t": _iso(r["t"]), "rx_bps": _f(r["rx"]), "tx_bps": _f(r["tx"]), "rx_bps_max": _f(r["rx_max"]), "tx_bps_max": _f(r["tx_max"]),
            "rx_util": _f(r["rx_util"]), "tx_util": _f(r["tx_util"]), "errors": int(r["errors"] or 0), "discards": int(r["discards"] or 0),
            "down": int(r["oper_min"] or 0) == 0, "gap": bool(r["gap"])} for r in rows]
    return {"source": src, "bucket_seconds": b, "points": pts, "start": t0.isoformat(), "end": t1.isoformat()}


async def stats(ch, sid: int, ifx: int, t0: datetime, t1: datetime, ret: dict) -> dict:
    """Min / average / max / 95th percentile per direction, data transferred, errors, discards and sample coverage.
    The 95th percentile is taken over 5-minute averages (the usual capacity / billing definition) when the 5-minute
    rollup covers the window, else over hourly averages (said in `p95_basis`)."""
    src = source_for(t0, t1, ret)
    p = {"sid": sid, "ifx": ifx, "t0": t0, "t1": t1, "reset": RESET}
    if src == "raw":
        r = (await ch.aquery(
            "SELECT count() AS o_samples, countIf(rx_bps IS NOT NULL) AS o_rated, min(rx_bps) AS o_rx_min, avg(rx_bps) AS o_rx_avg, max(rx_bps) AS o_rx_max, "
            "min(tx_bps) AS o_tx_min, avg(tx_bps) AS o_tx_avg, max(tx_bps) AS o_tx_max, sum(ifNull(rx_bps, 0) * interval_s) / 8 AS o_rx_bytes, "
            "sum(ifNull(tx_bps, 0) * interval_s) / 8 AS o_tx_bytes, max(rx_util) AS o_rx_util_max, max(tx_util) AS o_tx_util_max, "
            "sum(ifNull(in_errors, 0)) AS o_in_errors, sum(ifNull(out_errors, 0)) AS o_out_errors, sum(ifNull(in_discards, 0)) AS o_in_discards, "
            "sum(ifNull(out_discards, 0)) AS o_out_discards FROM switch_if_samples WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} "
            "AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} AND bitAnd(flags, {reset:UInt8}) = 0", p))[0]
        bytes_basis = "exact (rate × interval of every valid sample)"
    else:
        table, col = ("switch_if_5m", "bucket") if src == "5m" else ("switch_if_hourly", "hour")
        bits = "sum(rx_bits) / 8 AS o_rx_bytes, sum(tx_bits) / 8 AS o_tx_bytes" if src == "5m" else \
            "sum(rx_bps_sum) * 60 / 8 AS o_rx_bytes, sum(tx_bps_sum) * 60 / 8 AS o_tx_bytes"
        mins = "min(rx_bps_min) AS o_rx_min, min(tx_bps_min) AS o_tx_min" if src == "5m" else "NULL AS o_rx_min, NULL AS o_tx_min"
        r = (await ch.aquery(
            f"SELECT sum(samples) AS o_samples, sum(rated) AS o_rated, {mins}, if(sum(rated) > 0, sum(rx_bps_sum) / sum(rated), NULL) AS o_rx_avg, "
            "if(sum(rated) > 0, sum(tx_bps_sum) / sum(rated), NULL) AS o_tx_avg, if(sum(rated) > 0, max(rx_bps_max), NULL) AS o_rx_max, "
            f"if(sum(rated) > 0, max(tx_bps_max), NULL) AS o_tx_max, {bits}, max(rx_util_max) AS o_rx_util_max, max(tx_util_max) AS o_tx_util_max, "
            "sum(in_errors) AS o_in_errors, sum(out_errors) AS o_out_errors, sum(in_discards) AS o_in_discards, sum(out_discards) AS o_out_discards "
            f"FROM {table} WHERE switch_id = {{sid:UInt32}} AND ifindex = {{ifx:UInt32}} AND {col} >= {{t0:DateTime64(3)}} AND {col} < {{t1:DateTime64(3)}}",
            p))[0]
        bytes_basis = "exact (5-minute sums)" if src == "5m" else "estimated from hourly averages (assumes 60 s samples)"
    # 95th percentile of 5-minute (or hourly) averages
    p95_table = "5m" if (datetime.now(timezone.utc) - t0).total_seconds() <= ret["five_min_days"] * 86400 else "hourly"
    if p95_table == "5m":
        q = await ch.aquery(
            "SELECT quantileExact(0.95)(rx) AS rx_p95, quantileExact(0.95)(tx) AS tx_p95 FROM (SELECT bucket, sum(rx_bps_sum) / sum(rated) AS rx, "
            "sum(tx_bps_sum) / sum(rated) AS tx FROM switch_if_5m WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} "
            "AND bucket >= {t0:DateTime64(3)} AND bucket < {t1:DateTime64(3)} GROUP BY bucket HAVING sum(rated) > 0)", p)
    else:
        q = await ch.aquery(
            "SELECT quantileExact(0.95)(rx) AS rx_p95, quantileExact(0.95)(tx) AS tx_p95 FROM (SELECT hour, sum(rx_bps_sum) / sum(rated) AS rx, "
            "sum(tx_bps_sum) / sum(rated) AS tx FROM switch_if_hourly WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} "
            "AND hour >= {t0:DateTime64(3)} AND hour < {t1:DateTime64(3)} GROUP BY hour HAVING sum(rated) > 0)", p)
    rated = int(r["o_rated"] or 0)
    d = lambda k: _f(r[k]) if rated else None  # noqa: E731
    return {"source": src, "samples": int(r["o_samples"] or 0), "rated_samples": rated,
            "rx": {"min": d("o_rx_min"), "avg": d("o_rx_avg"), "max": d("o_rx_max"), "p95": _f(q[0]["rx_p95"]) if q and rated else None,
                   "bytes": _f(r["o_rx_bytes"], 0) if rated else None, "util_max": _f(r["o_rx_util_max"])},
            "tx": {"min": d("o_tx_min"), "avg": d("o_tx_avg"), "max": d("o_tx_max"), "p95": _f(q[0]["tx_p95"]) if q and rated else None,
                   "bytes": _f(r["o_tx_bytes"], 0) if rated else None, "util_max": _f(r["o_tx_util_max"])},
            "errors": {"in": int(r["o_in_errors"] or 0), "out": int(r["o_out_errors"] or 0)},
            "discards": {"in": int(r["o_in_discards"] or 0), "out": int(r["o_out_discards"] or 0)},
            "p95_basis": "5-minute averages" if p95_table == "5m" else "hourly averages", "bytes_basis": bytes_basis}


def compare_window(kind: str, t0: datetime, t1: datetime) -> tuple[datetime, datetime] | None:
    if kind == "previous":
        span = t1 - t0
        return t0 - span, t0
    if kind == "day":
        return t0 - timedelta(days=1), t1 - timedelta(days=1)
    if kind == "week":
        return t0 - timedelta(days=7), t1 - timedelta(days=7)
    return None
