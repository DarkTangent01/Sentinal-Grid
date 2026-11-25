"""Monitoring the monitor: health of the NMS's own processes and data freshness, as service-level objectives.

Every worker / poller process records its own figures (event-loop lag, CPU, memory, polls in flight, the duration
and last run of each periodic loop) and writes them to ClickHouse `nms_self_metrics` once a minute from its loop
monitor. Nothing is shared between containers. slo_status() combines the newest figures with database-derived ones
(device poll freshness, rollup lag) into pass / fail objectives used by the Monitoring Health page, /api/metrics and
the nms_self_slo_breach rule.
"""
from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timezone

SELF: dict[str, float] = {}
SELF_COLS = ["ts", "service", "instance", "metric", "value"]
_cpu = {"wall": time.monotonic(), "cpu": sum(os.times()[:2])}

SLO = {   # objective → (target, comparison, unit, label)
    "switch_freshness_pct": (99.0, ">=", "%", "Switches with fresh metrics"),
    "wlc_freshness_pct": (99.0, ">=", "%", "Wireless controllers with fresh metrics"),
    "loop_lag_p95_s": (0.5, "<=", "s", "Worst event-loop lag p95 (worker / pollers)"),
    "alert_pass_s": (300.0, "<=", "s", "Alert evaluation pass"),
    "rollup_age_s": (900.0, "<=", "s", "Wireless client rollup age"),
    "processes_reporting": (1.0, ">=", "", "Worker / poller processes reporting"),
}


def put(name: str, value: float) -> None:
    SELF[name] = float(value)


def add(name: str, value: float = 1.0) -> None:
    SELF[name] = SELF.get(name, 0.0) + value


def service_name() -> str:
    if os.environ.get("SELFMON_SERVICE"):            # services outside the worker roles (flows collector)
        return os.environ["SELFMON_SERVICE"].strip().lower()[:32]
    roles = (os.environ.get("WORKER_ROLES") or "all").strip().lower()
    return {"snmp": "poller", "core": "worker"}.get(roles, "worker")


def _process_figures() -> dict[str, float]:
    now_w, now_c = time.monotonic(), sum(os.times()[:2])
    dw = now_w - _cpu["wall"]
    out = {"cpu_pct": round(100 * (now_c - _cpu["cpu"]) / dw, 1) if dw > 0 else 0.0}
    _cpu.update(wall=now_w, cpu=now_c)
    try:
        from .platform.procstats import rss_mib
        out["rss_mib"] = float(rss_mib())
    except Exception:
        pass
    import sys
    pol = sys.modules.get("app.switches.poller")
    if pol is not None:
        out["polls_in_flight"] = float(len(pol._inflight))
        out["wireless_jobs_in_flight"] = float(len(pol._inflight_wireless))
    return out


async def flush(ch, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    rows = [{"ts": now, "service": service_name(), "instance": socket.gethostname()[:64], "metric": k, "value": v}
            for k, v in {**SELF, **_process_figures()}.items()]
    await ch.ainsert("nms_self_metrics", rows, SELF_COLS)
    return len(rows)


def _ok(key: str, value: float | None) -> bool | None:
    if value is None:
        return None
    target, cmp_, _, _ = SLO[key]
    return value >= target if cmp_ == ">=" else value <= target


async def latest(ch, minutes: int = 10) -> list[dict]:
    rows = await ch.aquery("SELECT service, instance, metric, argMax(value, ts) AS v, max(ts) AS t FROM nms_self_metrics "
                           "WHERE ts >= now() - INTERVAL {m:UInt32} MINUTE GROUP BY service, instance, metric", {"m": minutes})
    by: dict[tuple, dict] = {}
    for r in rows:
        d = by.setdefault((r["service"], r["instance"]), {"service": r["service"], "instance": r["instance"], "last": str(r["t"]), "metrics": {}})
        d["metrics"][r["metric"]] = float(r["v"])
        d["last"] = max(d["last"], str(r["t"]))
    return sorted(by.values(), key=lambda x: (x["service"], x["instance"]))


async def slo_status(s, ch, now: datetime | None = None) -> dict:
    from sqlalchemy import select

    from .db.models import Switch
    from .switches.alerts import stale_after
    from .switches.poller import is_wlc
    now = now or datetime.now(timezone.utc)
    sws = (await s.execute(select(Switch).where(Switch.monitoring == "active", Switch.state == "up"))).scalars().all()
    fresh = {"switch": [0, 0], "wlc": [0, 0]}
    stale = []
    for sw in sws:
        k = "wlc" if is_wlc(sw) else "switch"
        fresh[k][1] += 1
        last = sw.last_success_at
        last = last if last is None or last.tzinfo else last.replace(tzinfo=timezone.utc)
        if last and (now - last).total_seconds() <= stale_after(sw):
            fresh[k][0] += 1
        else:
            stale.append({"id": sw.id, "name": sw.name, "age_s": round((now - last).total_seconds()) if last else None, "limit_s": round(stale_after(sw))})
    procs = await latest(ch)
    m = lambda name: [p["metrics"][name] for p in procs if name in p["metrics"]]  # noqa: E731
    lag = m("loop_lag_p95_s")
    alert = m("loop_seconds:alert evaluation")
    rollup_runs = m("loop_last_run:wireless client rollup")
    values = {
        "switch_freshness_pct": round(100 * fresh["switch"][0] / fresh["switch"][1], 2) if fresh["switch"][1] else None,
        "wlc_freshness_pct": round(100 * fresh["wlc"][0] / fresh["wlc"][1], 2) if fresh["wlc"][1] else None,
        "loop_lag_p95_s": round(max(lag), 3) if lag else None,
        "alert_pass_s": round(max(alert), 1) if alert else None,
        "rollup_age_s": round(now.timestamp() - max(rollup_runs)) if rollup_runs else None,
        "processes_reporting": float(len(procs)),
    }
    slos = [{"key": k, "label": SLO[k][3], "value": v, "target": SLO[k][0], "comparison": SLO[k][1], "unit": SLO[k][2], "ok": _ok(k, v)}
            for k, v in values.items()]
    return {"generated_at": now.isoformat(), "slos": slos, "processes": procs, "stale_devices": sorted(stale, key=lambda x: -(x["age_s"] or 1e9))[:50],
            "devices": {k: {"fresh": a, "total": b} for k, (a, b) in fresh.items()}}

