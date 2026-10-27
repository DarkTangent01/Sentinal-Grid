"""Policy counter deltas and usage assessment (pure functions, unit-tested)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class CounterPoint:
    ts: datetime
    uuid: str
    hit_count: int | None
    bytes: int | None
    packets: int | None


def counter_deltas(points: list[CounterPoint]) -> dict:
    """Sum non-negative increments between consecutive snapshots.

    A decrease (reboot, 'diagnose firewall iprope clear', policy re-created) or a UUID change (policy ID reused)
    is treated as a reset: the new value itself is the increment since the reset."""
    pts = sorted(points, key=lambda p: p.ts)
    out = {"hits": 0, "bytes": 0, "packets": 0, "resets": 0, "intervals": 0, "first": pts[0].ts if pts else None,
           "last": pts[-1].ts if pts else None, "uuid_changes": 0}
    for prev, cur in zip(pts, pts[1:]):
        out["intervals"] += 1
        reused = prev.uuid and cur.uuid and prev.uuid != cur.uuid
        if reused:
            out["uuid_changes"] += 1
        for key, field in (("hits", "hit_count"), ("bytes", "bytes"), ("packets", "packets")):
            a, b = getattr(prev, field), getattr(cur, field)
            if a is None or b is None:
                continue
            if reused or b < a:
                if key == "hits":
                    out["resets"] += 1
                out[key] += b
            else:
                out[key] += b - a
    return out


STATES = ("in_use", "no_observed_hits", "potentially_unused", "unknown", "disabled", "not_assessable")


def assess(*, policy: dict, window_start: datetime, window_end: datetime, counters: dict | None,
           counter_last_used: datetime | None, siem_matches: int, siem_last_seen: datetime | None,
           ingest_since: datetime | None, min_days: int = 30) -> dict:
    """Combine firewall counters and SIEM log matches without adding them together (they describe the same traffic).

    counters: output of counter_deltas() over the window, or None when the hit-count API is unavailable.
    ingest_since: earliest traffic log ingested for this firewall (log coverage start), or None."""
    reasons = []
    if policy.get("status") != "enable":
        return {"state": "disabled", "method": "configuration", "confidence": "high", "reasons": ["policy is disabled"]}
    if policy.get("type") not in (None, "firewall"):
        return {"state": "not_assessable", "method": "-", "confidence": "-", "reasons": [f"policy type {policy.get('type')} not supported"]}

    # observation coverage
    counter_cov = None
    if counters and counters.get("first") and counters["intervals"] > 0:
        counter_cov = (min(counters["last"], window_end) - max(counters["first"], window_start))
    log_cov = None
    logtraffic = policy.get("logtraffic", "utm")
    if ingest_since:
        log_cov = window_end - max(ingest_since, window_start)
    min_cov = timedelta(days=min_days)

    # evidence of use
    if counters and counters["hits"] > 0:
        return {"state": "in_use", "method": "firewall hit counter", "confidence": "high",
                "reasons": [f"{counters['hits']:,} hits counted by the firewall in the window"]}
    if counter_last_used and counter_last_used >= window_start:
        return {"state": "in_use", "method": "firewall last-used timestamp", "confidence": "high",
                "reasons": [f"firewall reports last use at {counter_last_used.isoformat()}"]}
    if siem_matches > 0:
        return {"state": "in_use", "method": "SIEM log matches", "confidence": "high" if logtraffic == "all" else "medium",
                "reasons": [f"{siem_matches:,} matching traffic logs ingested (last {siem_last_seen.isoformat() if siem_last_seen else 'n/a'})"]}

    # no hits observed: decide how much that means
    if counters is not None and counter_cov is not None:
        if counter_cov >= min_cov:
            reasons.append(f"firewall counter did not increase over {counter_cov.days} days of snapshots")
            return {"state": "potentially_unused", "method": "firewall hit counter", "confidence": "high", "reasons": reasons}
        reasons.append(f"only {counter_cov.days} days of counter snapshots (need {min_days})")
    if logtraffic == "all" and log_cov is not None:
        if log_cov >= min_cov and counters is None:
            return {"state": "potentially_unused", "method": "SIEM log matches", "confidence": "medium",
                    "reasons": reasons + [f"no matching traffic logs over {log_cov.days} days with logtraffic=all"]}
        return {"state": "no_observed_hits", "method": "SIEM log matches" if counters is None else "counter + logs",
                "confidence": "low", "reasons": reasons + [f"no matches in {max(log_cov.days, 0)} days of log coverage (need {min_days})"]}
    if counters is not None and counter_cov is not None:
        return {"state": "no_observed_hits", "method": "firewall hit counter", "confidence": "low", "reasons": reasons}
    if logtraffic != "all":
        reasons.append(f"policy logging is '{logtraffic}', so not every session is logged")
    if log_cov is None:
        reasons.append("no traffic logs ingested from this firewall")
    if counters is None:
        reasons.append("firewall hit counters not available")
    return {"state": "unknown", "method": "insufficient telemetry", "confidence": "-", "reasons": reasons}
