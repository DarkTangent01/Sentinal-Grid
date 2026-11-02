"""Network analytics for Sentinel NMS (docs/NMS.md): availability / SLA, capacity forecasting, 95th percentile,
top-N, device health scores, inventory and alert analytics.

Built only from data the collectors already store (switch_metrics / switch_if_* in ClickHouse, switch rows, events,
alerts and service-check results). Nothing here polls a device. A value that was never measured is returned as null
(and left out of averages), never as 0: a device with no samples in the range has availability null, not 0 %.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, NmsService, Switch, SwitchEvent, SwitchInterface
from ..products import nms_rule_clause

RANGES = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
SEV_ORDER = ["informational", "low", "medium", "high", "critical"]


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _iso(v):
    v = _aware(v)
    return v.isoformat() if v else None


def window(range_: str, now: datetime) -> tuple[datetime, datetime]:
    return now - timedelta(days=RANGES.get(range_, 7)), now


def _r(v, nd=2):
    return None if v is None or (isinstance(v, float) and math.isnan(v)) else round(float(v), nd)


async def devices(s: AsyncSession, site: str | None = None, vendor: str | None = None, role: str | None = None) -> list[Switch]:
    rows = (await s.execute(select(Switch).order_by(Switch.name))).scalars().all()
    return [x for x in rows if (not site or (x.site or "").lower() == site.lower()) and (not vendor or x.vendor == vendor)
            and (not role or (x.role or "").lower() == role.lower())]


# ------------------------------------------------------------------ pure helpers (tested directly)
def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float, float] | None:
    """Least squares y = a + b·x → (a, b, r²); None with fewer than 3 points or no spread in x."""
    n = len(points)
    if n < 3:
        return None
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    sxx = sum((p[0] - mx) ** 2 for p in points)
    if sxx == 0:
        return None
    sxy = sum((p[0] - mx) * (p[1] - my) for p in points)
    b = sxy / sxx
    a = my - b * mx
    syy = sum((p[1] - my) ** 2 for p in points)
    r2 = 1.0 if syy == 0 else max(0.0, 1 - sum((p[1] - (a + b * p[0])) ** 2 for p in points) / syy)
    return a, b, r2


def forecast(daily: list[tuple[float, float]], threshold: float, horizon_days: float = 365, min_points: int = 7) -> dict:
    """Zabbix timeleft(): daily values (day number, value) → trend per day and days until `threshold`.
    days_left is 0 when already over, None when the trend is flat / falling, beyond the horizon, or data is too thin."""
    pts = [(x, y) for x, y in daily if y is not None]
    out = {"points": len(pts), "current": _r(pts[-1][1]) if pts else None, "slope_per_day": None, "r2": None, "days_left": None,
           "confidence": "insufficient_data"}
    if len(pts) < min_points:
        return out
    fit = linear_fit(pts)
    if fit is None:
        return out
    a, b, r2 = fit
    out.update(slope_per_day=_r(b, 3), r2=_r(r2, 2), confidence="high" if r2 >= 0.7 else "medium" if r2 >= 0.4 else "low")
    if pts[-1][1] >= threshold:
        out["days_left"] = 0
    elif b > 0:
        x_hit = (threshold - a) / b
        left = x_hit - pts[-1][0]
        out["days_left"] = _r(max(0.0, left), 1) if left <= horizon_days else None
    return out


def health_score(sw: Switch, *, open_alerts: list[str] | None = None, if_errors: int = 0, now: datetime | None = None) -> dict:
    """0-100 device health (100 = nothing wrong). Every deduction is listed, so the score is explainable."""
    now = now or datetime.now(timezone.utc)
    if sw.monitoring != "active":
        return {"score": None, "grade": "paused", "reasons": ["monitoring paused"]}
    if sw.state == "down":
        return {"score": 0, "grade": "critical", "reasons": ["device unreachable"]}
    score, reasons = 100.0, []

    def ded(n, why):
        nonlocal score
        score -= n
        reasons.append(f"-{n}: {why}")
    if sw.state == "auth_failed":
        ded(60, "SNMP authentication failing (no fresh data)")
    elif sw.state == "unknown":
        ded(20, "never polled successfully")
    last = _aware(sw.last_success_at)
    if sw.state == "up" and (not last or (now - last).total_seconds() > 3 * max(60, sw.poll_interval_seconds or 60) + 120):
        ded(15, "metrics stale")
    for v, label in ((sw.cpu_pct, "CPU"), (sw.mem_pct, "memory")):
        if v is not None and v >= 90:
            ded(20, f"{label} {v:.0f}%")
        elif v is not None and v >= 75:
            ded(8, f"{label} {v:.0f}%")
    h = sw.health or {}
    env = h.get("environment") or {}
    bad = [x["name"] for k in ("psus", "fans") for x in env.get(k) or [] if x.get("state") not in ("ok", "absent", "unknown")]
    if bad:
        ded(min(40, 20 * len(bad)), f"failed fan / PSU: {', '.join(bad[:3])}")
    hot = [t["name"] for t in env.get("temperatures") or [] if t.get("state") in ("warning", "critical", "shutdown")]
    if hot:
        ded(15, f"temperature alarm: {', '.join(hot[:3])}")
    full = [v["name"] for v in h.get("storage") or [] if (v.get("pct") or 0) >= 90]
    if full:
        ded(10, f"storage ≥ 90 %: {', '.join(full[:3])}")
    if if_errors:
        ded(min(20, 5 * if_errors), f"{if_errors} interface(s) with errors")
    stack = h.get("stack") or {}
    if any(not m.get("healthy") for m in stack.get("members") or []):
        ded(15, "stack member not ready")
    sev = [a for a in open_alerts or [] if a in ("high", "critical")]
    if sev:
        ded(min(30, 10 * len(sev)), f"{len(sev)} open high / critical alert(s)")
    if sw.coverage_pct is not None and sw.coverage_pct < 50:
        ded(10, f"metric coverage {sw.coverage_pct:.0f}%")
    score = max(0.0, score)
    grade = "healthy" if score >= 90 else "fair" if score >= 70 else "poor" if score >= 40 else "critical"
    return {"score": round(score), "grade": grade, "reasons": reasons}


def p95(values: list[float]) -> float | None:
    vs = sorted(v for v in values if v is not None)
    if not vs:
        return None
    k = max(0, math.ceil(0.95 * len(vs)) - 1)   # nearest-rank, as billing systems compute it
    return vs[k]


# ------------------------------------------------------------------ availability / SLA
async def availability(s: AsyncSession, ch, *, range_: str, sla: float, site=None, vendor=None, role=None) -> dict:
    now = datetime.now(timezone.utc)
    t0, t1 = window(range_, now)
    sws = [x for x in await devices(s, site, vendor, role) if x.monitoring == "active"]
    ids = [x.id for x in sws] or [0]
    rows = await ch.aquery(
        "SELECT switch_id, sum(samples) AS n, sum(total) AS up FROM switch_metrics_hourly WHERE metric = 'switch_up' "
        "AND hour >= toStartOfHour({t0:DateTime64(3)}) AND switch_id IN {ids:Array(UInt32)} GROUP BY switch_id", {"t0": t0, "ids": ids})
    by = {int(r["switch_id"]): (int(r["n"]), float(r["up"])) for r in rows}
    evs = (await s.execute(select(SwitchEvent).where(SwitchEvent.kind == "reachable", SwitchEvent.at >= t0, SwitchEvent.switch_id.in_(ids)))).scalars().all()
    outages: dict[int, list[float]] = defaultdict(list)
    for e in evs:
        if (e.data or {}).get("outage_s") is not None:
            outages[e.switch_id].append(float(e.data["outage_s"]))
    items = []
    for sw in sws:
        n, up = by.get(sw.id, (0, 0.0))
        pct = 100.0 * up / n if n else None
        down_now = sw.state == "down"
        outs = outages.get(sw.id, [])
        downtime = sum(outs) + ((now - (_aware(sw.state_since) or now)).total_seconds() if down_now else 0)
        items.append({"switch_id": sw.id, "name": sw.name, "site": sw.site, "vendor": sw.vendor, "role": sw.role, "state": sw.state,
                      "availability_pct": _r(pct, 3), "samples": n, "outages": len(outs) + (1 if down_now else 0), "downtime_s": round(downtime),
                      "longest_outage_s": round(max(outs + [0.0])), "sla_met": None if pct is None else pct >= sla})
    sites: dict[str, dict] = {}
    for it in items:
        k = it["site"] or "(no site)"
        d = sites.setdefault(k, {"site": k, "devices": 0, "measured": 0, "sum": 0.0, "breaches": 0, "outages": 0, "downtime_s": 0})
        d["devices"] += 1
        d["outages"] += it["outages"]
        d["downtime_s"] += it["downtime_s"]
        if it["availability_pct"] is not None:
            d["measured"] += 1
            d["sum"] += it["availability_pct"]
            d["breaches"] += not it["sla_met"]
    site_rows = [{"site": d["site"], "devices": d["devices"], "availability_pct": _r(d["sum"] / d["measured"], 3) if d["measured"] else None,
                  "sla_breaches": d["breaches"], "outages": d["outages"], "downtime_s": d["downtime_s"]} for d in sites.values()]
    measured = [x["availability_pct"] for x in items if x["availability_pct"] is not None]
    svc = await service_availability(s, ch, t0)
    allowed = (1 - sla / 100) * (t1 - t0).total_seconds()
    return {"range": range_, "sla_target_pct": sla, "allowed_downtime_s": round(allowed),
            "summary": {"devices": len(items), "measured": len(measured), "unmeasured": len(items) - len(measured),
                        "fleet_availability_pct": _r(sum(measured) / len(measured), 3) if measured else None,
                        "sla_breaches": sum(1 for x in items if x["sla_met"] is False), "outages": sum(x["outages"] for x in items),
                        "downtime_s": sum(x["downtime_s"] for x in items),
                        "services_availability_pct": _r(sum(x["availability_pct"] for x in svc if x["availability_pct"] is not None)
                                                        / max(1, sum(1 for x in svc if x["availability_pct"] is not None)), 3)
                        if any(x["availability_pct"] is not None for x in svc) else None},
            "devices": sorted(items, key=lambda x: (x["availability_pct"] is None, x["availability_pct"] if x["availability_pct"] is not None else 0)),
            "sites": sorted(site_rows, key=lambda x: (x["availability_pct"] is None, x["availability_pct"] or 0)), "services": svc}


async def service_availability(s: AsyncSession, ch, t0: datetime) -> list[dict]:
    svcs = (await s.execute(select(NmsService).order_by(NmsService.name))).scalars().all()
    if not svcs:
        return []
    rows = await ch.aquery("SELECT service_id, count() AS n, countIf(state != 'critical') AS ok, avg(latency_ms) AS lat, "
                           "quantile(0.95)(latency_ms) AS p95 FROM service_results WHERE ts >= {t0:DateTime64(3)} GROUP BY service_id", {"t0": t0})
    by = {int(r["service_id"]): r for r in rows}
    out = []
    for x in svcs:
        r = by.get(x.id)
        n = int(r["n"]) if r else 0
        out.append({"service_id": x.id, "name": x.name, "kind": x.kind, "target": x.target, "state": x.state if x.enabled else "paused",
                    "checks": n, "availability_pct": _r(100.0 * int(r["ok"]) / n, 3) if n else None,
                    "latency_avg_ms": _r(r["lat"], 1) if r else None, "latency_p95_ms": _r(r["p95"], 1) if r else None})
    return out


# ------------------------------------------------------------------ capacity forecasting
async def capacity(s: AsyncSession, ch, *, days: int, threshold_if: float, threshold_dev: float, site=None, vendor=None, role=None,
                   limit: int = 100) -> dict:
    now = datetime.now(timezone.utc)
    t0 = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    sws = {x.id: x for x in await devices(s, site, vendor, role) if x.monitoring == "active"}
    ids = list(sws) or [0]
    day0 = t0.date()
    rows = await ch.aquery(
        "SELECT switch_id, ifindex, toDate(hour) AS d, max(greatest(rx_util_max, tx_util_max)) AS peak, "
        "sum(rx_bps_sum + tx_bps_sum) / greatest(sum(rated), 1) AS avg_bps "
        "FROM switch_if_hourly WHERE hour >= {t0:DateTime64(3)} AND switch_id IN {ids:Array(UInt32)} AND rated > 0 "
        "GROUP BY switch_id, ifindex, d ORDER BY switch_id, ifindex, d", {"t0": t0, "ids": ids})
    series: dict[tuple, list] = defaultdict(list)
    for r in rows:
        d = r["d"] if not isinstance(r["d"], str) else datetime.fromisoformat(r["d"]).date()
        series[(int(r["switch_id"]), int(r["ifindex"]))].append(((d - day0).days, float(r["peak"])))
    ifs = {(i.switch_id, i.ifindex): i for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids)))).scalars()}
    if_items = []
    for (sid, ix), pts in series.items():
        f = forecast(pts, threshold_if, min_points=min(7, max(3, days // 2)))
        if f["days_left"] is None and (f["current"] or 0) < threshold_if * 0.75:
            continue
        i = ifs.get((sid, ix))
        if_items.append({"switch_id": sid, "switch": sws[sid].name, "site": sws[sid].site, "ifindex": ix, "name": i.name if i else str(ix),
                         "alias": i.alias if i else "", "speed_bps": i.speed_bps if i else None, "metric": "peak utilisation %",
                         "threshold": threshold_if, **f})
    drow = await ch.aquery(
        "SELECT switch_id, metric, component, toDate(hour) AS d, sum(total) / sum(samples) AS v FROM switch_metrics_hourly "
        "WHERE hour >= {t0:DateTime64(3)} AND switch_id IN {ids:Array(UInt32)} AND metric IN "
        "('switch_cpu_utilization_percent', 'switch_memory_utilization_percent', 'switch_storage_used_percent') "
        "GROUP BY switch_id, metric, component, d ORDER BY switch_id, metric, component, d", {"t0": t0, "ids": ids})
    dser: dict[tuple, list] = defaultdict(list)
    for r in drow:
        d = r["d"] if not isinstance(r["d"], str) else datetime.fromisoformat(r["d"]).date()
        dser[(int(r["switch_id"]), r["metric"], r["component"])].append(((d - day0).days, float(r["v"])))
    label = {"switch_cpu_utilization_percent": "CPU %", "switch_memory_utilization_percent": "memory %", "switch_storage_used_percent": "storage used %"}
    dev_items = []
    for (sid, metric, comp), pts in dser.items():
        f = forecast(pts, threshold_dev, min_points=min(7, max(3, days // 2)))
        if f["days_left"] is None:
            continue
        dev_items.append({"switch_id": sid, "switch": sws[sid].name, "site": sws[sid].site, "metric": label[metric], "component": comp,
                          "threshold": threshold_dev, **f})
    key = lambda x: (x["days_left"] is None, x["days_left"] if x["days_left"] is not None else 1e9, -(x["current"] or 0))  # noqa: E731
    poe = []
    for sw in sws.values():
        if sw.poe_budget_w and sw.poe_used_w is not None:
            poe.append({"switch_id": sw.id, "switch": sw.name, "site": sw.site, "budget_w": _r(sw.poe_budget_w, 1), "used_w": _r(sw.poe_used_w, 1),
                        "headroom_w": _r(sw.poe_budget_w - sw.poe_used_w, 1), "pct": _r(100 * sw.poe_used_w / sw.poe_budget_w, 1)})
    return {"days": days, "interface_threshold_pct": threshold_if, "device_threshold_pct": threshold_dev,
            "summary": {"interfaces_at_risk_30d": sum(1 for x in if_items if x["days_left"] is not None and x["days_left"] <= 30),
                        "interfaces_over_threshold": sum(1 for x in if_items if x["days_left"] == 0),
                        "devices_at_risk_30d": sum(1 for x in dev_items if x["days_left"] is not None and x["days_left"] <= 30),
                        "interfaces_analysed": len(series), "device_series_analysed": len(dser)},
            "interfaces": sorted(if_items, key=key)[:limit], "devices": sorted(dev_items, key=key)[:limit],
            "poe": sorted(poe, key=lambda x: -(x["pct"] or 0))[:limit]}


# ------------------------------------------------------------------ top-N and 95th percentile
TOP_IF = {
    "peak_util": ("max(greatest(rx_util_max, tx_util_max))", "peak utilisation %"),
    "avg_util": None,   # derived from bps and speed below
    "traffic": ("sum(rx_bps_sum + tx_bps_sum) / greatest(sum(rated), 1)", "average bit/s (in + out)"),
    "errors": ("sum(in_errors + out_errors + crc)", "errors + CRC"),
    "discards": ("sum(in_discards + out_discards)", "discards"),
    "down": ("sum(down_samples)", "samples down"),
}
TOP_DEV = {"cpu": "switch_cpu_utilization_percent", "memory": "switch_memory_utilization_percent", "temperature": "switch_temperature_celsius",
           "storage": "switch_storage_used_percent", "poll_time": "switch_poll_duration_seconds"}


async def top_interfaces(s: AsyncSession, ch, *, range_: str, by: str, limit: int, site=None, vendor=None, role=None) -> dict:
    now = datetime.now(timezone.utc)
    t0, _ = window(range_, now)
    sws = {x.id: x for x in await devices(s, site, vendor, role)}
    ids = list(sws) or [0]
    if by == "p95":
        rows = await ch.aquery(
            "SELECT switch_id, ifindex, quantile(0.95)(rx_bps) AS rx95, quantile(0.95)(tx_bps) AS tx95, max(rx_bps) AS rxmax, max(tx_bps) AS txmax, "
            "count() AS n FROM switch_if_samples WHERE ts >= {t0:DateTime64(3)} AND switch_id IN {ids:Array(UInt32)} AND rx_bps IS NOT NULL "
            "GROUP BY switch_id, ifindex ORDER BY greatest(rx95, tx95) DESC LIMIT {lim:UInt32}", {"t0": max(t0, now - timedelta(days=35)), "ids": ids,
                                                                                                    "lim": limit})
        val = lambda r: max(float(r["rx95"] or 0), float(r["tx95"] or 0))  # noqa: E731
        unit = "95th percentile bit/s (max of in / out)"
    else:
        expr, unit = TOP_IF.get(by) or TOP_IF["peak_util"]
        if by == "avg_util":
            expr, unit = "sum(rx_bps_sum + tx_bps_sum) / greatest(sum(rated), 1)", "average utilisation %"
        rows = await ch.aquery(f"SELECT switch_id, ifindex, {expr} AS v, sum(rated) AS n FROM switch_if_hourly WHERE hour >= {{t0:DateTime64(3)}} "
                               f"AND switch_id IN {{ids:Array(UInt32)}} GROUP BY switch_id, ifindex HAVING v > 0 ORDER BY v DESC LIMIT {{lim:UInt32}}",
                               {"t0": t0, "ids": ids, "lim": limit * (4 if by == "avg_util" else 1)})
        val = lambda r: float(r["v"])  # noqa: E731
    ifs = {(i.switch_id, i.ifindex): i for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids)))).scalars()}
    items = []
    for r in rows:
        sid, ix = int(r["switch_id"]), int(r["ifindex"])
        i = ifs.get((sid, ix))
        v = val(r)
        if by == "avg_util":
            if not i or not i.speed_bps:
                continue
            v = 100.0 * (v / 2) / i.speed_bps   # average of in and out against the link speed
        it = {"switch_id": sid, "switch": sws[sid].name if sid in sws else str(sid), "site": sws[sid].site if sid in sws else "", "ifindex": ix,
              "name": i.name if i else str(ix), "alias": i.alias if i else "", "speed_bps": i.speed_bps if i else None, "value": _r(v, 2)}
        if by == "p95":
            it.update(rx_p95_bps=_r(r["rx95"]), tx_p95_bps=_r(r["tx95"]), rx_max_bps=_r(r["rxmax"]), tx_max_bps=_r(r["txmax"]), samples=int(r["n"]),
                      p95_util_pct=_r(100.0 * v / i.speed_bps, 2) if i and i.speed_bps else None)
        items.append(it)
    items.sort(key=lambda x: -(x["value"] or 0))
    return {"range": range_, "by": by, "unit": unit, "items": items[:limit]}


async def top_devices(s: AsyncSession, ch, *, range_: str, by: str, limit: int, site=None, vendor=None, role=None) -> dict:
    now = datetime.now(timezone.utc)
    t0, _ = window(range_, now)
    metric = TOP_DEV.get(by, TOP_DEV["cpu"])
    sws = {x.id: x for x in await devices(s, site, vendor, role)}
    ids = list(sws) or [0]
    rows = await ch.aquery(
        "SELECT switch_id, component, sum(total) / sum(samples) AS avg, max(vmax) AS peak FROM switch_metrics_hourly "
        "WHERE metric = {m:String} AND hour >= toStartOfHour({t0:DateTime64(3)}) AND switch_id IN {ids:Array(UInt32)} "
        "GROUP BY switch_id, component ORDER BY peak DESC LIMIT {lim:UInt32}", {"m": metric, "t0": t0, "ids": ids, "lim": limit * 3})
    best: dict[int, dict] = {}
    for r in rows:
        sid = int(r["switch_id"])
        cur = best.get(sid)
        if cur is None or float(r["peak"]) > cur["peak"]:
            best[sid] = {"switch_id": sid, "switch": sws[sid].name, "site": sws[sid].site, "vendor": sws[sid].vendor, "model": sws[sid].model,
                         "component": r["component"], "avg": _r(r["avg"]), "peak": _r(r["peak"])}
    return {"range": range_, "by": by, "metric": metric, "items": sorted(best.values(), key=lambda x: -(x["peak"] or 0))[:limit]}


# ------------------------------------------------------------------ health scores
async def health(s: AsyncSession, *, site=None, vendor=None, role=None) -> dict:
    now = datetime.now(timezone.utc)
    sws = await devices(s, site, vendor, role)
    alerts = (await s.execute(select(Alert.evidence, Alert.severity).where(Alert.status.in_(["new", "investigating"]), nms_rule_clause(Alert.rule_key)))).all()
    by_sw: dict[int, list[str]] = defaultdict(list)
    for ev, sev in alerts:
        sid = (ev or {}).get("switch_id")
        if isinstance(sid, int):
            by_sw[sid].append(sev)
    errs = Counter(i.switch_id for i in (await s.execute(select(SwitchInterface).where(
        SwitchInterface.present.is_(True), (SwitchInterface.in_errors_delta + SwitchInterface.out_errors_delta) > 0))).scalars())
    items = []
    for sw in sws:
        h = health_score(sw, open_alerts=by_sw.get(sw.id), if_errors=errs.get(sw.id, 0), now=now)
        items.append({"switch_id": sw.id, "name": sw.name, "site": sw.site, "vendor": sw.vendor, "model": sw.model, "role": sw.role,
                      "state": sw.state, **h})
    scored = [x["score"] for x in items if x["score"] is not None]
    grades = Counter(x["grade"] for x in items)
    sites: dict[str, list] = defaultdict(list)
    for x in items:
        if x["score"] is not None:
            sites[x["site"] or "(no site)"].append(x["score"])
    return {"summary": {"devices": len(items), "average": _r(sum(scored) / len(scored), 1) if scored else None, "grades": dict(grades)},
            "sites": sorted(({"site": k, "devices": len(v), "average": _r(sum(v) / len(v), 1), "worst": min(v)} for k, v in sites.items()),
                            key=lambda x: x["average"]),
            "devices": sorted(items, key=lambda x: (x["score"] is None, x["score"] if x["score"] is not None else 0))}


# ------------------------------------------------------------------ inventory
async def inventory(s: AsyncSession, *, unused_days: int = 30, site=None, vendor=None, role=None) -> dict:
    now = datetime.now(timezone.utc)
    sws = await devices(s, site, vendor, role)
    ids = [x.id for x in sws] or [0]

    def dist(key):
        return [{"value": k or "(unknown)", "count": n} for k, n in Counter(key(x) for x in sws).most_common()]
    fw_by_model: dict[str, Counter] = defaultdict(Counter)
    for x in sws:
        if x.model:
            fw_by_model[x.model][x.firmware or "(unknown)"] += 1
    drift = []
    for model, c in fw_by_model.items():
        if len(c) > 1:
            common = c.most_common(1)[0][0]
            outliers = [x for x in sws if x.model == model and (x.firmware or "(unknown)") != common]
            drift.append({"model": model, "versions": [{"firmware": f, "count": n} for f, n in c.most_common()], "most_common": common,
                          "outliers": [{"switch_id": x.id, "name": x.name, "firmware": x.firmware} for x in outliers][:50]})
    ups = [(x, x.uptime_ticks / 100 / 86400) for x in sws if x.uptime_ticks is not None and x.state == "up"]
    buckets = Counter("< 1 day" if d < 1 else "1-7 days" if d < 7 else "7-30 days" if d < 30 else "30-180 days" if d < 180
                      else "180-365 days" if d < 365 else "> 1 year" for _, d in ups)
    ifs = (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids), SwitchInterface.present.is_(True),
                                                         SwitchInterface.kind == "physical"))).scalars().all()
    cutoff = now - timedelta(days=unused_days)
    unused = [i for i in ifs if i.oper != "up" and i.admin == "up" and _aware(i.last_change_at) and _aware(i.last_change_at) < cutoff]
    by_id = {x.id: x for x in sws}
    per_dev: dict[int, dict] = {}
    for i in ifs:
        d = per_dev.setdefault(i.switch_id, {"switch_id": i.switch_id, "name": by_id[i.switch_id].name, "site": by_id[i.switch_id].site,
                                             "ports": 0, "up": 0, "admin_down": 0, "unused": 0})
        d["ports"] += 1
        d["up"] += i.oper == "up"
        d["admin_down"] += i.admin == "down"
    for i in unused:
        per_dev[i.switch_id]["unused"] += 1
    for d in per_dev.values():
        d["in_use_pct"] = _r(100.0 * d["up"] / d["ports"], 1) if d["ports"] else None
    speeds = Counter(_speed(i.speed_bps) for i in ifs if i.oper == "up")
    return {"summary": {"devices": len(sws), "vendors": len({x.vendor for x in sws}), "models": len({x.model for x in sws if x.model}),
                        "firmware_versions": len({x.firmware for x in sws if x.firmware}), "models_with_firmware_drift": len(drift),
                        "physical_ports": len(ifs), "ports_up": sum(1 for i in ifs if i.oper == "up"),
                        "ports_admin_down": sum(1 for i in ifs if i.admin == "down"), "ports_unused": len(unused),
                        "long_uptime_devices": sum(1 for _, d in ups if d >= 365)},
            "by_vendor": dist(lambda x: x.vendor), "by_model": dist(lambda x: x.model), "by_os": dist(lambda x: x.os),
            "by_firmware": dist(lambda x: f"{x.model or '?'} {x.firmware}".strip() if x.firmware else ""), "by_site": dist(lambda x: x.site),
            "by_role": dist(lambda x: x.role), "firmware_drift": sorted(drift, key=lambda x: -len(x["outliers"])),
            "uptime": [{"bucket": b, "count": buckets.get(b, 0)} for b in ("< 1 day", "1-7 days", "7-30 days", "30-180 days", "180-365 days", "> 1 year")],
            "long_uptime": sorted(({"switch_id": x.id, "name": x.name, "firmware": x.firmware, "uptime_days": _r(d, 0)} for x, d in ups if d >= 365),
                                  key=lambda x: -x["uptime_days"])[:50],
            "port_speeds": [{"speed": k, "count": n} for k, n in speeds.most_common()],
            "ports_by_device": sorted(per_dev.values(), key=lambda d: -(d["in_use_pct"] or 0)),
            "unused_ports": [{"switch_id": i.switch_id, "switch": by_id[i.switch_id].name, "ifindex": i.ifindex, "name": i.name, "alias": i.alias,
                              "down_since": _iso(i.last_change_at)} for i in sorted(unused, key=lambda i: _aware(i.last_change_at))][:500],
            "unused_days": unused_days}


def _speed(bps) -> str:
    if not bps:
        return "unknown"
    for n, label in ((1e11, "100G"), (4e10, "40G"), (2.5e10, "25G"), (1e10, "10G"), (5e9, "5G"), (2.5e9, "2.5G"), (1e9, "1G"), (1e8, "100M"), (1e7, "10M")):
        if bps >= n:
            return label
    return f"{bps / 1e6:.0f}M"


# ------------------------------------------------------------------ alerts and events
async def alert_analytics(s: AsyncSession, *, range_: str) -> dict:
    now = datetime.now(timezone.utc)
    t0, _ = window(range_, now)
    rows = (await s.execute(select(Alert).where(nms_rule_clause(Alert.rule_key), Alert.first_seen >= t0).limit(20000))).scalars().all()
    per_day: dict[str, Counter] = defaultdict(Counter)
    rules = Counter()
    rule_names = {}
    devs = Counter()
    sites = Counter()
    durations = defaultdict(list)
    for a in rows:
        per_day[_aware(a.first_seen).strftime("%Y-%m-%d")][a.severity] += 1
        rules[a.rule_key] += 1
        rule_names[a.rule_key] = a.name
        ev = a.evidence or {}
        name = ev.get("switch") or ev.get("service") or ev.get("wlc") or ev.get("target")
        if name:
            devs[str(name)] += 1
        for x in a.sites or []:
            sites[x] += 1
        if a.status == "resolved":
            durations[a.rule_key].append((_aware(a.last_seen) - _aware(a.first_seen)).total_seconds())
    reopen = sorted(({"rule": a.rule_key, "name": a.name, "group_key": a.group_key, "reopened": a.open_seq} for a in rows if a.open_seq >= 2),
                    key=lambda x: -x["reopened"])[:20]
    days = [(t0 + timedelta(days=i)).strftime("%Y-%m-%d") for i in range((now - t0).days + 1)]
    all_d = [d for v in durations.values() for d in v]
    evs = (await s.execute(select(SwitchEvent.kind, SwitchEvent.at).where(SwitchEvent.at >= t0).limit(100000))).all()
    ev_kinds = Counter(k for k, _ in evs)
    return {"range": range_, "summary": {"alerts": len(rows), "open": sum(1 for a in rows if a.status in ("new", "investigating")),
                                         "resolved": sum(1 for a in rows if a.status == "resolved"),
                                         "mttr_s": round(sum(all_d) / len(all_d)) if all_d else None, "events": len(evs)},
            "per_day": [{"day": d, **{k: per_day[d].get(k, 0) for k in SEV_ORDER}} for d in days],
            "top_rules": [{"rule": k, "name": rule_names[k], "count": n,
                           "mttr_s": round(sum(durations[k]) / len(durations[k])) if durations[k] else None} for k, n in rules.most_common(15)],
            "top_devices": [{"name": k, "count": n} for k, n in devs.most_common(15)],
            "top_sites": [{"site": k, "count": n} for k, n in sites.most_common(15)],
            "flapping_alerts": reopen, "event_kinds": [{"kind": k, "count": n} for k, n in ev_kinds.most_common(20)]}
