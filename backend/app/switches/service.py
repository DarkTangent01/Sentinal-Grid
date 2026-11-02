"""Read side of switch monitoring: inventory rows, overview, histories. All numbers come from stored poll results;
missing measurements are returned as null (never 0)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, Switch, SwitchCredential, SwitchEvent, SwitchInterface, SwitchPollRun
from .poller import intervals_of
from .rates import GAP, RESET, flag_names
from .registry import GROUPS, coverage, describe

RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
RAW_MAX_SECONDS = 2 * 86400  # longer ranges read the hourly rollups


def window(range_: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    now = now or datetime.now(timezone.utc)
    return now - timedelta(seconds=RANGES[range_]), now


def bucket(t0: datetime, t1: datetime, minimum: int = 60) -> int:
    span = (t1 - t0).total_seconds()
    for b in (60, 120, 300, 600, 900, 1800, 3600, 10800, 21600, 43200):
        if b >= minimum and span / b <= 360:
            return b
    return 86400


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _iso(v):
    v = _aware(v)
    return v.isoformat() if v else None


def _f(v, nd=2):
    if v is None or (isinstance(v, float) and v != v):
        return None
    return round(float(v), nd)


def freshness(sw: Switch, now: datetime) -> str:
    if sw.monitoring != "active":
        return "paused"
    last = _aware(sw.last_success_at)
    if last is None:
        return "never"
    return "fresh" if (now - last).total_seconds() <= 3 * max(60, sw.poll_interval_seconds or 60) + 60 else "stale"


def switch_row(sw: Switch, now: datetime, cred_names: dict[int, dict] | None = None, alerts: dict[int, dict] | None = None) -> dict:
    h = sw.health or {}
    cov = h.get("coverage") or {}
    a = (alerts or {}).get(sw.id) or {}
    poe = h.get("poe") or {}
    return {"id": sw.id, "name": sw.name, "hostname": sw.sys_name, "address": sw.address, "port": sw.port, "vendor": sw.vendor, "family": sw.family,
            "model": sw.model, "serial": sw.serial, "serials": h.get("serials") or ([sw.serial] if sw.serial else []), "firmware": sw.firmware, "os": sw.os,
            "site": sw.site, "building": sw.building, "floor": sw.floor, "rack": sw.rack, "role": sw.role, "location": sw.location, "notes": sw.notes,
            "parent_id": sw.parent_id,
            "snmp_version": ((cred_names or {}).get(sw.credential_id or 0) or {}).get("version"), "credential_id": sw.credential_id,
            "credential": ((cred_names or {}).get(sw.credential_id or 0) or {}).get("name"),
            "monitoring": sw.monitoring, "state": sw.state, "state_since": _iso(sw.state_since), "freshness": freshness(sw, now),
            "uptime_s": sw.uptime_ticks / 100 if sw.uptime_ticks is not None else None, "last_poll_at": _iso(sw.last_poll_at),
            "last_success_at": _iso(sw.last_success_at), "last_error": sw.last_error, "last_error_kind": sw.last_error_kind,
            "poll_duration_ms": sw.poll_duration_ms, "poll_interval_seconds": sw.poll_interval_seconds, "if_total": sw.if_total, "if_up": sw.if_up,
            "if_errors": sw.if_errors, "cpu_pct": _f(sw.cpu_pct, 1), "mem_pct": _f(sw.mem_pct, 1), "temp_max_c": _f(sw.temp_max_c, 1),
            "poe_budget_w": _f(sw.poe_budget_w, 1), "poe_used_w": _f(sw.poe_used_w, 1),
            "poe_pct": _f(100 * sw.poe_used_w / sw.poe_budget_w, 1) if sw.poe_budget_w and sw.poe_used_w is not None else None,
            "poe_supported": poe != {} and sw.poe_budget_w is not None, "coverage_pct": sw.coverage_pct, "coverage": cov,
            "alerts_open": a.get("count", 0), "alert_severity": a.get("severity"), "timeout_ms": sw.timeout_ms, "retries": sw.retries,
            "group_intervals": sw.group_intervals or {}, "thresholds": sw.thresholds or {}, "created_at": _iso(sw.created_at), "created_by": sw.created_by}


SEV = ["informational", "low", "medium", "high", "critical"]


async def open_alerts_by_switch(s: AsyncSession) -> dict[int, dict]:
    rows = (await s.execute(select(Alert.group_key, Alert.severity).where(Alert.rule_key.like("switch_%"),
                                                                          Alert.status.in_(["new", "investigating"])))).all()
    out: dict[int, dict] = {}
    for g, sev in rows:
        try:
            sid = int(str(g).split(":")[0])
        except ValueError:
            continue
        cur = out.setdefault(sid, {"count": 0, "severity": None})
        cur["count"] += 1
        if cur["severity"] is None or SEV.index(sev) > SEV.index(cur["severity"]):
            cur["severity"] = sev
    return out


async def credential_names(s: AsyncSession) -> dict[int, dict]:
    return {i: {"name": n, "version": v} for i, n, v in (await s.execute(select(SwitchCredential.id, SwitchCredential.name, SwitchCredential.version))).all()}


def matches(sw: Switch, site: list[str], vendor: list[str], model: str | None, q: str | None) -> bool:
    if site and sw.site not in site:
        return False
    if vendor and sw.vendor not in vendor:
        return False
    if model and model.lower() not in (sw.model or "").lower():
        return False
    if q:
        ql = q.lower()
        if not any(ql in (x or "").lower() for x in (sw.name, sw.address, sw.sys_name, sw.site, sw.model, sw.serial, sw.building)):
            return False
    return True


async def overview(s: AsyncSession, ch, *, site: list[str], vendor: list[str], model: str | None, q: str | None, range_: str, user=None) -> dict:
    from ..products import site_allowed
    now = datetime.now(timezone.utc)
    t0, _ = window(range_, now)
    sws = [x for x in (await s.execute(select(Switch).order_by(Switch.name))).scalars().all() if matches(x, site, vendor, model, q)
           and (user is None or site_allowed(user, x.site))]
    ids = [x.id for x in sws]
    alerts = await open_alerts_by_switch(s)
    creds = await credential_names(s)
    rows = [switch_row(x, now, creds, alerts) for x in sws]
    active = [r for r in rows if r["monitoring"] == "active"]
    ifs = (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids or [0]), SwitchInterface.present.is_(True)))).scalars().all()
    by_id = {x.id: x for x in sws}

    def ifrow(r: SwitchInterface) -> dict:
        sw = by_id[r.switch_id]
        return {"switch_id": sw.id, "switch": sw.name, "site": sw.site, "ifindex": r.ifindex, "name": r.name, "alias": r.alias, "kind": r.kind,
                "oper": r.oper, "speed_bps": r.speed_bps, "rx_bps": _f(r.rx_bps), "tx_bps": _f(r.tx_bps), "rx_util": _f(r.rx_util, 1),
                "tx_util": _f(r.tx_util, 1), "errors": (r.in_errors_delta or 0) + (r.out_errors_delta or 0) + (r.crc_delta or 0)
                if any(v is not None for v in (r.in_errors_delta, r.out_errors_delta, r.crc_delta)) else None,
                "crc": r.crc_delta, "discards": r.discards_delta, "flags": flag_names(r.sample_flags or 0)}
    util = sorted((ifrow(r) for r in ifs if (r.rx_util or r.tx_util) and freshness(by_id[r.switch_id], now) == "fresh"),
                  key=lambda x: -max(x["rx_util"] or 0, x["tx_util"] or 0))[:15]
    errs = sorted((ifrow(r) for r in ifs if ((r.in_errors_delta or 0) + (r.out_errors_delta or 0) + (r.crc_delta or 0)) > 0),
                  key=lambda x: -(x["errors"] or 0))[:15]
    evs = (await s.execute(select(SwitchEvent).where(SwitchEvent.switch_id.in_(ids or [0]), SwitchEvent.at >= t0)
                           .order_by(SwitchEvent.at.desc()).limit(5000))).scalars().all()
    flaps: dict = {}
    for e in evs:
        if e.kind in ("port_up", "port_down", "port_flap"):
            k = (e.switch_id, e.data.get("ifindex"))
            f = flaps.setdefault(k, {"switch_id": e.switch_id, "switch": by_id[e.switch_id].name, "ifindex": e.data.get("ifindex"),
                                     "name": e.component, "changes": 0, "last": _iso(e.at)})
            f["changes"] += 2 if e.kind == "port_flap" else 1
    flapping = sorted((f for f in flaps.values() if f["changes"] >= 4), key=lambda f: -f["changes"])[:15]
    env = []
    stp_lacp = []
    for sw in sws:
        h = sw.health or {}
        for kind in ("psus", "fans"):
            for x in ((h.get("environment") or {}).get(kind)) or []:
                if x.get("state") not in ("ok", "absent", "unknown"):
                    env.append({"switch_id": sw.id, "switch": sw.name, "component": x["name"], "kind": kind[:-1], "state": x["state"]})
        for t in ((h.get("environment") or {}).get("temperatures")) or []:
            if t.get("state") in ("warning", "critical", "shutdown") or (t.get("threshold") and t.get("celsius") is not None and t["celsius"] >= t["threshold"]):
                env.append({"switch_id": sw.id, "switch": sw.name, "component": t["name"], "kind": "temperature", "state": f"{t['celsius']} °C {t.get('state')}"})
        for lag in (((h.get("lacp") or {}).get("lags")) or {}).values():
            if any(m.get("in_bundle") is False for m in lag["members"]):
                stp_lacp.append({"switch_id": sw.id, "switch": sw.name, "kind": "lacp", "component": lag["name"],
                                 "detail": f"{lag['up_members']}/{lag['total_members']} members in bundle"})
        for m in ((h.get("stack") or {}).get("members")) or []:
            if not m.get("healthy"):
                stp_lacp.append({"switch_id": sw.id, "switch": sw.name, "kind": "stack", "component": f"unit {m['unit']}", "detail": m["state"]})
    for e in evs:
        if e.kind in ("stp_root_change",):
            stp_lacp.append({"switch_id": e.switch_id, "switch": by_id[e.switch_id].name, "kind": "stp", "component": e.component, "detail": e.detail, "at": _iso(e.at)})
    tc = {}
    for e in evs:
        if e.kind == "stp_topology_change":
            tc[e.switch_id] = tc.get(e.switch_id, 0) + int(e.data.get("count") or 1)
    for sid, n in sorted(tc.items(), key=lambda x: -x[1])[:10]:
        if n >= 10:
            stp_lacp.append({"switch_id": sid, "switch": by_id[sid].name, "kind": "stp", "component": "topology changes", "detail": f"{n} in {range_}"})
    pr = (await s.execute(select(SwitchPollRun.ok, func.count()).where(SwitchPollRun.switch_id.in_(ids or [0]), SwitchPollRun.started_at >= t0,
                                                                         SwitchPollRun.kind == "poll").group_by(SwitchPollRun.ok))).all()
    pr_ok = sum(n for ok, n in pr if ok)
    pr_all = sum(n for _, n in pr)
    sites: dict = {}
    for r in rows:
        k = r["site"] or "(no site)"
        x = sites.setdefault(k, {"site": k, "switches": 0, "down": 0, "alerts": 0, "events": 0})
        x["switches"] += 1
        x["down"] += r["state"] in ("down", "auth_failed")
        x["alerts"] += r["alerts_open"]
    for e in evs:
        if e.severity in ("medium", "high", "critical"):
            sites[by_id[e.switch_id].site or "(no site)"]["events"] += 1
    poe = sorted(({"switch_id": r["id"], "switch": r["name"], "budget_w": r["poe_budget_w"], "used_w": r["poe_used_w"], "pct": r["poe_pct"]}
                  for r in rows if r["poe_pct"] is not None), key=lambda x: -x["pct"])
    cpu_vals = [r["cpu_pct"] for r in active if r["cpu_pct"] is not None and r["freshness"] == "fresh"]
    mem_vals = [r["mem_pct"] for r in active if r["mem_pct"] is not None and r["freshness"] == "fresh"]
    return {
        "generated_at": now.isoformat(), "range": range_,
        "totals": {"switches": len(rows), "monitored": len(active), "online": sum(1 for r in active if r["state"] == "up"),
                   "offline": sum(1 for r in active if r["state"] == "down"), "auth_failed": sum(1 for r in active if r["state"] == "auth_failed"),
                   "unknown": sum(1 for r in active if r["state"] == "unknown"), "paused": len(rows) - len(active),
                   "critical_alerts": sum(1 for r in rows if r["alert_severity"] in ("critical", "high")),
                   "stale": sum(1 for r in active if r["freshness"] in ("stale", "never") and r["state"] == "up"),
                   "interfaces_with_errors": len(errs), "interfaces_flapping": len(flapping), "env_alarms": len(env), "stp_lacp_issues": len(stp_lacp),
                   "polling_success_pct": round(100 * pr_ok / pr_all, 1) if pr_all else None, "polls": pr_all,
                   "cpu_avg": round(sum(cpu_vals) / len(cpu_vals), 1) if cpu_vals else None, "cpu_max": max(cpu_vals) if cpu_vals else None,
                   "cpu_over_80": sum(1 for v in cpu_vals if v >= 80), "mem_avg": round(sum(mem_vals) / len(mem_vals), 1) if mem_vals else None,
                   "mem_over_80": sum(1 for v in mem_vals if v >= 80),
                   "poe_max_pct": poe[0]["pct"] if poe else None, "interfaces_over_80": sum(1 for x in util if max(x["rx_util"] or 0, x["tx_util"] or 0) >= 80)},
        "switches": rows, "top_utilization": util, "interface_errors": errs, "flapping": flapping, "environment": env, "stp_lacp": stp_lacp[:30],
        "poe": poe[:15], "sites": sorted(sites.values(), key=lambda x: (-(x["alerts"] + x["down"] * 10 + x["events"]), x["site"])),
        "events": [event_row(e, by_id) for e in evs[:100]],
        "filters": {"sites": sorted({x.site for x in (await s.execute(select(Switch))).scalars() if x.site}),
                    "vendors": sorted({x.vendor for x in sws}), "models": sorted({x.model for x in sws if x.model})}}


def event_row(e: SwitchEvent, by_id: dict | None = None) -> dict:
    sw = (by_id or {}).get(e.switch_id)
    return {"id": e.id, "switch_id": e.switch_id, "switch": sw.name if sw else None, "at": _iso(e.at), "kind": e.kind, "severity": e.severity,
            "component": e.component, "detail": e.detail, "data": e.data}


async def interface_series(ch, switch_id: int, ifindex: int, t0: datetime, t1: datetime) -> dict:
    span = (t1 - t0).total_seconds()
    p = {"sid": switch_id, "ifx": ifindex, "t0": t0, "t1": t1}
    if span <= RAW_MAX_SECONDS:
        b = bucket(t0, t1)
        rows = await ch.aquery(
            f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avg(rx_bps) AS o_rx_bps, max(rx_bps) AS o_rx_bps_max, avg(tx_bps) AS o_tx_bps, "
            "max(tx_bps) AS o_tx_bps_max, max(rx_util) AS o_rx_util, max(tx_util) AS o_tx_util, avg(rx_pps) AS o_rx_pps, avg(tx_pps) AS o_tx_pps, "
            "sum(in_errors) AS o_in_errors, sum(out_errors) AS o_out_errors, sum(crc) AS o_crc, sum(in_discards) AS o_in_discards, sum(out_discards) AS o_out_discards, "
            "min(oper) AS o_oper_min, max(bitAnd(flags, {gap:UInt8})) AS o_gap, count() AS o_n FROM switch_if_samples "
            "WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} "
            "AND bitAnd(flags, {reset:UInt8}) = 0 GROUP BY t ORDER BY t", {**p, "gap": GAP, "reset": RESET})
        source = "raw"
    else:
        b = max(3600, bucket(t0, t1, 3600))
        rows = await ch.aquery(
            f"SELECT toStartOfInterval(hour, INTERVAL {b} SECOND) AS t, sum(rx_bps_sum) / greatest(sum(rated), 1) AS o_rx_bps, max(rx_bps_max) AS o_rx_bps_max, "
            "sum(tx_bps_sum) / greatest(sum(rated), 1) AS o_tx_bps, max(tx_bps_max) AS o_tx_bps_max, max(rx_util_max) AS o_rx_util, max(tx_util_max) AS o_tx_util, "
            "sum(in_errors) AS o_in_errors, sum(out_errors) AS o_out_errors, sum(crc) AS o_crc, sum(in_discards) AS o_in_discards, "
            "sum(out_discards) AS o_out_discards, sum(down_samples) AS o_down, sum(samples) AS o_n, sum(rated) AS o_rated FROM switch_if_hourly "
            "WHERE switch_id = {sid:UInt32} AND ifindex = {ifx:UInt32} AND hour >= toStartOfHour({t0:DateTime64(3)}) AND hour < {t1:DateTime64(3)} "
            "GROUP BY t ORDER BY t", p)
        source = "hourly"
    pts = []
    for r in rows:
        pt = {"t": _iso(r["t"])}
        for k in ("rx_bps", "rx_bps_max", "tx_bps", "tx_bps_max", "rx_util", "tx_util", "rx_pps", "tx_pps"):
            pt[k] = _f(r.get("o_" + k))
        if source == "hourly" and not int(r.get("o_rated") or 0):
            for k in ("rx_bps", "tx_bps", "rx_bps_max", "tx_bps_max", "rx_util", "tx_util"):
                pt[k] = None
        for k in ("in_errors", "out_errors", "crc", "in_discards", "out_discards"):
            pt[k] = int(r["o_" + k]) if r.get("o_" + k) is not None else None
        pt["down"] = (int(r.get("o_oper_min") or 0) == 0) if source == "raw" else int(r.get("o_down") or 0) > 0
        pt["gap"] = bool(r.get("o_gap")) if source == "raw" else False
        pts.append(pt)
    return {"bucket_seconds": b, "source": source, "points": pts}


DEVICE_METRICS = {"cpu": "switch_cpu_utilization_percent", "memory": "switch_memory_utilization_percent", "temperature": "switch_temperature_celsius",
                  "poe_used": "switch_poe_power_watts", "poe_budget": "switch_poe_budget_watts", "up": "switch_up", "poll_duration": "switch_poll_duration_seconds",
                  "interfaces_up": "switch_interfaces_up", "macs": "switch_mac_table_entries", "stp_tc": "switch_stp_topology_changes_total",
                  "routes": "switch_route_count", "coverage": "switch_metric_coverage_percent"}


async def device_series(ch, switch_id: int, metric: str, t0: datetime, t1: datetime) -> dict:
    span = (t1 - t0).total_seconds()
    p = {"sid": switch_id, "m": DEVICE_METRICS[metric], "t0": t0, "t1": t1}
    if span <= RAW_MAX_SECONDS:
        b = bucket(t0, t1)
        rows = await ch.aquery(f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, component, avg(value) AS v, max(value) AS vmax, min(value) AS vmin "
                               "FROM switch_metrics WHERE switch_id = {sid:UInt32} AND metric = {m:String} AND ts >= {t0:DateTime64(3)} "
                               "AND ts < {t1:DateTime64(3)} GROUP BY t, component ORDER BY t", p)
    else:
        b = max(3600, bucket(t0, t1, 3600))
        rows = await ch.aquery(f"SELECT toStartOfInterval(hour, INTERVAL {b} SECOND) AS t, component, sum(total) / greatest(sum(samples), 1) AS v, "
                               "max(vmax) AS vmax, min(vmin) AS vmin FROM switch_metrics_hourly WHERE switch_id = {sid:UInt32} AND metric = {m:String} "
                               "AND hour >= toStartOfHour({t0:DateTime64(3)}) AND hour < {t1:DateTime64(3)} GROUP BY t, component ORDER BY t", p)
    series: dict[str, list] = {}
    for r in rows:
        series.setdefault(r["component"] or "", []).append({"t": _iso(r["t"]), "v": _f(r["v"]), "max": _f(r["vmax"]), "min": _f(r["vmin"])})
    return {"bucket_seconds": b, "metric": DEVICE_METRICS[metric], "series": [{"component": k, "points": v} for k, v in sorted(series.items())]}


def capability_view(sw: Switch, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ivs = intervals_of(sw)
    vendor = sw.vendor if sw.vendor in ("cisco", "fortinet", "juniper", "ruckus") else "generic"
    rows = describe(sw.capabilities or {}, vendor, now, ivs)
    groups = []
    for g, d in GROUPS.items():
        if g not in ivs:  # wireless groups exist only for controllers
            continue
        st = (sw.group_state or {}).get(g) or {}
        groups.append({"group": g, "label": d["label"], "interval_seconds": ivs[g], "last_run": st.get("last_run"), "ok": st.get("ok"),
                       "duration_ms": st.get("duration_ms"), "error": st.get("error"), "skipped": st.get("skipped", False)})
    return {"coverage": coverage(sw.capabilities or {}, now, ivs), "metrics": rows, "groups": groups}
