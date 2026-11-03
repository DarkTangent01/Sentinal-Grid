"""Execute YAML rules: against the events table (alert engine), as a dry run over history (no alerts), and against
their embedded test cases (inline rows through ClickHouse format(), the same SQL as production)."""
from __future__ import annotations

import json
import re
import string
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .compiler import compile_rule, inline_source
from .schema import FIELDS, NUMERIC, Rule, parse_duration

SOURCE_ID_BASE = 1_000_000   # firewall_id at or above this belongs to a generic log source, not a firewall
TEST_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
TEST_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


class _SafeFormat(string.Formatter):
    """{name} lookups only; unknown names render as '?'."""
    def get_field(self, field_name, args, kwargs):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field_name):
            return "?", field_name
        return kwargs.get(field_name, "?"), field_name


def _num(v: float) -> str:
    return f"{int(v):,}" if float(v).is_integer() else f"{v:,.2f}"


def explain(rule: Rule, row: dict, threshold: float) -> str:
    c = rule.detection.condition
    vals = {g: row[f"g_{g}"] for g in c.group_by}
    ctx = {**vals, "metric": _num(row["metric"]), "threshold": _num(threshold), "events": row["events"],
           "timeframe": f"{c.timeframe // 60} min" if c.timeframe >= 60 else f"{c.timeframe} s",
           "samples": ", ".join(str(x) for x in (row.get("samples") or [])[:10])}
    if rule.explanation:
        return _SafeFormat().format(rule.explanation, **ctx)
    what = ("events" if c.count is not None else f"distinct {c.distinct_count.field}" if c.distinct_count else f"{c.sum.field} (sum)")  # type: ignore[union-attr]
    who = ", ".join(f"{k}={v}" for k, v in vals.items())
    return f"{rule.name}: {who} — {ctx['metric']} {what} in {ctx['timeframe']} (threshold {ctx['threshold']})."


def _aware(v) -> datetime:
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def to_detections(rule: Rule, rows: list[dict], threshold: float, origin: str):
    from ..alerts.engine import Detection
    c = rule.detection.condition
    out = []
    for r in rows:
        vals = {g: r[f"g_{g}"] for g in c.group_by}
        ev = {"rule_id": rule.id, "rule_version": rule.version, "origin": origin, "group": vals, "metric": r["metric"], "threshold": threshold,
              "events": int(r["events"]), "samples": list(r.get("samples") or [])[:20], "data_sources": rule.data_sources,
              "falsepositives": rule.falsepositives, "troubleshooting": rule.investigation, "tags": rule.tags}
        flt: dict[str, Any] = {"category": [rule.log_source.category]}
        for g in ("src_ip", "dst_ip", "user", "src_mac"):
            if vals.get(g):
                flt[g] = vals[g]
        if rule.log_source.event_type:
            flt["event_type"] = [rule.log_source.event_type]
        out.append(Detection(
            group_key=f"{rule.id}:" + "|".join(str(vals[g]) for g in c.group_by), count=int(r["events"]),
            first_seen=_aware(r["first_seen"]), last_seen=_aware(r["last_seen"]), explanation=explain(rule, r, threshold),
            src_ip=vals.get("src_ip") or None, dst_ip=vals.get("dst_ip") or None,
            firewall_ids=sorted(int(x) for x in (r.get("firewall_ids") or []) if 0 < int(x) < SOURCE_ID_BASE),
            sites=sorted(x for x in (r.get("sites") or []) if x), evidence=ev, event_filter=flt))
    return out


async def execute(ch, rule: Rule, now: datetime, params: dict, cidrs: list[str], origin: str = "builtin") -> tuple[list, dict]:
    """Run against `events` over the rule's time frame (at least one evaluation interval, so no gap between runs)."""
    c = rule.detection.condition
    window = max(c.timeframe, int(params.get("interval_minutes") or 0) * 60)
    thr = float(params.get("threshold") or c.threshold)
    q = compile_rule(rule, t0=now - timedelta(seconds=window), t1=now, cidrs=cidrs, threshold=thr)
    t = time.monotonic()
    rows = await ch.aquery(q.sql, q.params)
    stats = {"last_run": now.isoformat(), "duration_ms": round((time.monotonic() - t) * 1000, 1), "matches": len(rows),
             "window_s": window, "rule_version": rule.version}
    return to_detections(rule, rows, thr, origin), stats


async def dry_run(ch, rule: Rule, now: datetime, hours: int, cidrs: list[str], threshold: float | None = None) -> dict:
    """Historical replay: evaluate every time-frame window over the last `hours` (capped at 7 days, 2000 windows)
    and return the groups that would have alerted. Nothing is written."""
    c = rule.detection.condition
    step = c.timeframe
    hours = max(1, min(hours, 168))
    n = min(2000, (hours * 3600) // step)
    thr = float(threshold or c.threshold)
    t = time.monotonic()
    hits: dict[str, dict] = {}
    # one query per window would be slow; instead evaluate the whole range bucketed by window in a single pass
    q = compile_rule(rule, t0=now - timedelta(seconds=step * n), t1=now, cidrs=cidrs, threshold=thr, limit=1000)
    sql = q.sql.replace("GROUP BY ", f"GROUP BY toStartOfInterval(`event_time`, toIntervalSecond({int(step)})) AS bucket, ", 1)
    sql = sql.replace("SELECT ", "SELECT bucket, ", 1)
    rows = await ch.aquery(sql, q.params)
    for r in rows:
        key = "|".join(str(r[f"g_{g}"]) for g in c.group_by)
        h = hits.setdefault(key, {"group": {g: r[f"g_{g}"] for g in c.group_by}, "windows": 0, "max_metric": 0.0, "first": None, "last": None,
                                  "explanation": explain(rule, r, thr)})
        h["windows"] += 1
        h["max_metric"] = max(h["max_metric"], float(r["metric"]))
        h["first"] = min(filter(None, [h["first"], str(r["first_seen"])]))
        h["last"] = max(filter(None, [h["last"], str(r["last_seen"])]))
    return {"rule_id": rule.id, "hours": hours, "window_s": step, "threshold": thr, "groups": len(hits),
            "alerting_windows": sum(h["windows"] for h in hits.values()), "duration_ms": round((time.monotonic() - t) * 1000, 1),
            "results": sorted(hits.values(), key=lambda h: -h["windows"])[:200],
            "note": "bucketed by fixed windows; the live engine uses a sliding window, so it can alert slightly more often"}


# ------------------------------------------------------------------ embedded tests
def _expand(ev: dict, rule: Rule, now: datetime = TEST_NOW) -> list[dict]:
    """One test event spec → rows. `repeat: N`; a field given as {seq: [a, b]} becomes a, a+1 … b (numbers) or
    a.1 … a.N style IPs when `{ipseq: ["10.0.0.", 1, 50]}`; `at: "-30s"` places it relative to TEST_NOW."""
    spec = dict(ev)
    repeat = int(spec.pop("repeat", 1))
    at = spec.pop("at", "-10s")
    seqs: dict[str, list] = {}
    for k, v in list(spec.items()):
        if isinstance(v, dict) and "seq" in v:
            a, b = v["seq"]
            seqs[k] = list(range(int(a), int(b) + 1))
        elif isinstance(v, dict) and "ipseq" in v:
            prefix, a, b = v["ipseq"]
            seqs[k] = [f"{prefix}{i}" for i in range(int(a), int(b) + 1)]
    count = max([repeat] + [len(x) for x in seqs.values()])
    sign = -1 if str(at).startswith("-") else 1
    t = now + timedelta(seconds=sign * parse_duration(str(at).lstrip("+-")))
    rows = []
    for i in range(min(count, 5000)):
        row = {k: v for k, v in spec.items() if k not in seqs}
        for k, vals in seqs.items():
            row[k] = vals[i % len(vals)]
        row.setdefault("category", rule.log_source.category)
        if rule.log_source.event_type:
            row.setdefault("event_type", rule.log_source.event_type)
        row["event_time"] = (t - timedelta(milliseconds=i)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        for k in row:
            if k != "event_time" and k not in FIELDS:
                raise ValueError(f"test event field {k!r} is not an event column")
        rows.append({k: (v if k in NUMERIC or k == "event_time" else str(v)) for k, v in row.items()})
    return rows


async def run_tests(ch, rule: Rule) -> list[dict]:
    """Run each embedded test case through the production SQL against inline rows; returns per-test results."""
    results = []
    src, sparams = inline_source()
    for tc in rule.tests:
        try:
            now = _aware(tc.now) if tc.now else TEST_NOW
            rows = [r for ev in tc.events for r in _expand(ev, rule, now)]
            window = rule.detection.condition.timeframe
            q = compile_rule(rule, t0=now - timedelta(seconds=window), t1=now + timedelta(seconds=1), cidrs=TEST_CIDRS,
                             source=src, source_params={**sparams, "data": "\n".join(json.dumps(r) for r in rows)})
            out = await ch.aquery(q.sql, q.params)
            groups = [{g: r[f"g_{g}"] for g in rule.detection.condition.group_by} for r in out]
            ok = len(out) == tc.expect_alerts and all(any(all(str(g.get(k)) == str(v) for k, v in want.items()) for g in groups)
                                                      for want in tc.expect_groups)
            results.append({"name": tc.name, "passed": ok, "alerts": len(out), "expected": tc.expect_alerts, "groups": groups, "rows": len(rows)})
        except Exception as e:  # a broken test case is a failed test, never a crash of the caller
            results.append({"name": tc.name, "passed": False, "error": f"{type(e).__name__}: {e}"})
    return results
