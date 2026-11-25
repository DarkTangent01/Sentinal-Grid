"""Sentinel NMS report sections (policy hygiene, ISP SLA, firewall health, VPN tunnels, BGP, availability, capacity,
wireless, NMS alerts, configuration changes, rogue APs, network compliance), registered with the report framework
(app/reports.py)."""
from __future__ import annotations

import html as h
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Alert
from ..reports import _fmt, _table, register

NMS_SECTIONS = ["nms_availability", "nms_capacity_risks", "wireless_usage", "nms_alerts", "config_changes", "rogue_aps", "network_compliance"]


def _range_key(start: datetime, end: datetime) -> str:
    days = (end - start).total_seconds() / 86400
    return "24h" if days <= 1.5 else "7d" if days <= 10 else "30d" if days <= 45 else "90d"


def _dur(sec) -> str:
    sec = int(sec or 0)
    return f"{sec // 3600}h {sec % 3600 // 60}m" if sec >= 3600 else f"{sec // 60}m"


async def _nms_parts(s: AsyncSession, ch: ClickHouse, start: datetime, end: datetime, sections: list[str], summary: dict) -> list[str]:
    from . import analytics as NA
    parts: list[str] = []
    rk = _range_key(start, end)
    if "nms_availability" in sections:
        a = await NA.availability(s, ch, range_=rk, sla=99.9)
        sm = a["summary"]
        summary["nms_availability"] = {k: sm.get(k) for k in ("fleet_availability_pct", "sla_breaches", "outages")}
        worst = [x for x in a["devices"] if x["availability_pct"] is not None][:15]
        parts.append(f"<h2>Network availability ({rk})</h2>" + _table(["Metric", "Value"], [
            ["Fleet availability", f"{sm.get('fleet_availability_pct')}%" if sm.get("fleet_availability_pct") is not None else "—"],
            ["Devices below the 99.9% SLA", sm.get("sla_breaches")], ["Outages", sm.get("outages")], ["Total downtime", _dur(sm.get("downtime_s"))],
            ["Service checks availability", f"{sm.get('services_availability_pct')}%" if sm.get("services_availability_pct") is not None else "—"]])
            + "<h3 style='font-size:13px'>Least available devices</h3>"
            + _table(["Device", "Site", "Availability", "Outages", "Downtime", "Longest"],
                     [[x["name"], x["site"] or "—", f"{x['availability_pct']}%", x["outages"], _dur(x["downtime_s"]), _dur(x["longest_outage_s"])] for x in worst]))
    if "nms_capacity_risks" in sections:
        c = await NA.capacity(s, ch, days=30, threshold_if=80, threshold_dev=90, limit=15)
        rows = []
        for kind, items, label in (("Interface", c["interfaces"], lambda x: f"{x['switch']} {x['name']}"), ("Device", c["devices"], lambda x: f"{x['switch']} {x['metric']}"),
                                   ("PoE", c.get("poe_forecast", []), lambda x: f"{x['switch']} {x['component']}"), ("AP clients", c.get("ap_load", []), lambda x: x["ap"])):
            for x in items:
                if x["days_left"] is not None and x["days_left"] <= 90:
                    rows.append([kind, label(x), x["current"], x["threshold"], "now" if x["days_left"] == 0 else f"{x['days_left']} days", x["confidence"]])
        summary["nms_capacity_risks"] = len(rows)
        parts.append("<h2>Capacity risks (next 90 days)</h2>" + _table(["Kind", "Item", "Now", "Threshold", "Reaches threshold", "Confidence"], rows[:40]))
    if "wireless_usage" in sections:
        from ..wireless import client_analytics as WA
        from ..wireless import service as WS
        wlcs = [w.id for w in await WS.controllers(s)]
        if wlcs:
            sc = WA.Scope(tz="UTC", t0=start, t1=end, wlc_ids=wlcs)
            rk_ = await WA.rankings(ch, sc, {a.id: a for a in (await WS.load(s))[2].values()}, top=10)
            ss = rk_["ssids"]["unique_clients"]
            summary["wireless_usage"] = {"ssids": len(ss), "unique_clients": sum(x["unique_clients"] for x in ss)}
            parts.append("<h2>Wireless usage</h2>" + _table(["SSID", "Unique clients", "Sessions", "Peak concurrent", "Average concurrent"],
                                                          [[x["ssid"] or "(none)", x["unique_clients"], x["sessions"], x["peak_clients"], x["avg_clients"]] for x in ss])
                         + "<h3 style='font-size:13px'>Busiest access points</h3>"
                         + _table(["AP", "Unique clients", "Peak concurrent", "Average"], [[x["ap_name"], x["unique_clients"], x["peak_clients"], x["avg_clients"]]
                                                                                          for x in rk_["aps"]["unique_clients"]]))
    if "nms_alerts" in sections:
        from ..products import nms_rule_clause
        rows = (await s.execute(select(Alert.name, Alert.severity, func.count(Alert.id)).where(
            Alert.last_seen >= start, Alert.first_seen < end, nms_rule_clause(Alert.rule_key)).group_by(Alert.name, Alert.severity)
            .order_by(func.count(Alert.id).desc()).limit(25))).all()
        summary["nms_alerts"] = sum(r[2] for r in rows)
        parts.append(f"<h2>Network alerts ({summary['nms_alerts']})</h2>" + _table(["Detection", "Severity", "Alerts"], [list(r) for r in rows]))
    if "config_changes" in sections:
        from ..db.models import DeviceConfigSnapshot, Switch
        rows = (await s.execute(select(Switch.name, DeviceConfigSnapshot.taken_at, DeviceConfigSnapshot.added, DeviceConfigSnapshot.removed,
                                       DeviceConfigSnapshot.trigger).join(Switch, Switch.id == DeviceConfigSnapshot.switch_id).where(
            DeviceConfigSnapshot.taken_at >= start, DeviceConfigSnapshot.taken_at < end, DeviceConfigSnapshot.trigger != "first")
            .order_by(DeviceConfigSnapshot.taken_at.desc()).limit(50))).all()
        summary["config_changes"] = len(rows)
        parts.append(f"<h2>Configuration changes ({len(rows)})</h2>" + _table(["Device", "When (UTC)", "Lines added", "Lines removed", "Found by"],
                                                                             [[r[0], f"{r[1]:%Y-%m-%d %H:%M}", r[2], r[3], r[4]] for r in rows]))
    if "rogue_aps" in sections:
        from ..db.models import WirelessRogue
        rs = (await s.execute(select(WirelessRogue).where(WirelessRogue.last_seen >= start, WirelessRogue.first_seen < end)
                              .order_by(WirelessRogue.rssi_dbm.desc().nulls_last()).limit(200))).scalars().all()
        flagged = [r for r in rs if r.class_type == "malicious" or r.spoofs_ssid or r.on_network]
        summary["rogue_aps"] = {"heard": len(rs), "flagged": len(flagged)}
        parts.append(f"<h2>Rogue access points ({len(flagged)} flagged of {len(rs)} heard)</h2>"
                     + _table(["BSSID", "SSID", "Why", "Strongest (dBm)", "Heard by", "Controller class"],
                              [[r.mac, r.ssid or "hidden", ", ".join(w for w, x in (("malicious", r.class_type == "malicious"), ("spoofs our SSID", r.spoofs_ssid),
                                                                                    ("on wired network", r.on_network)) if x), r.rssi_dbm if r.rssi_dbm is not None else "—",
                                r.detecting_ap or "—", r.class_type or "—"] for r in flagged[:40]]))
    if "network_compliance" in sections:
        from collections import Counter

        from ..db.models import NetComplianceResult
        from ..netcompliance import engine as NC
        from ..netcompliance.checks import BY_ID
        run = await NC.latest_run(s)
        if not run:
            summary["network_compliance"] = None
            parts.append("<h2>Network compliance</h2><p>No compliance evaluation has run yet.</p>")
        else:
            rows = list((await s.execute(select(NetComplianceResult).where(NetComplianceResult.run_id == run.id))).scalars())
            exc = await NC.active_exceptions(s)
            fws = NC.framework_summary([(r.device_kind, r.device_id, r.results) for r in rows], exc)
            fails: Counter = Counter()
            for r in rows:
                for x in r.results:
                    if NC.status_with_exceptions(x, r.device_kind, r.device_id, exc) == "fail":
                        fails[x["check"]] += 1
            from ..netcompliance.frameworks import FRAMEWORKS
            summary["network_compliance"] = {k: v["score"] for k, v in fws.items()}
            pct = lambda v: "—" if v is None else f"{v}%"
            parts.append(f"<h2>Network compliance ({run.devices} devices, evaluated {run.started_at:%Y-%m-%d %H:%M} UTC)</h2>"
                         + _table(["Framework", "Score (met / evaluated)", "Evidence coverage", "Met", "Not met", "No evidence", "Excepted"],
                                  [[FRAMEWORKS[k]["name"], pct(v["score"]), pct(v["coverage"]), v["pass"], v["fail"], v["not_evaluated"], v["excepted"]]
                                   for k, v in fws.items()])
                         + "<h3 style='font-size:13px'>Most failed checks</h3>"
                         + _table(["Check", "Severity", "Devices failing"],
                                  [[f"{k} {BY_ID[k].title}", BY_ID[k].severity, n] for k, n in fails.most_common(15)]))
    return parts



async def _policy_hygiene(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    from ..api.policies import _rows
    try:
        rows = await _rows(s, ch, 30)
    except Exception:
        rows = []
    bad = [r for r in rows if r["assessment"]["state"] in ("potentially_unused", "no_observed_hits") or r["analysis"].get("worst")]
    parts.append(f"<h2>Firewall policy hygiene (30-day window, {len(rows)} policies)</h2>" + _table(
        ["Firewall", "Policy", "Name", "Usage", "Shadow", "Logging"],
        [[r["firewall"], r["policyid"], r["name"], r["assessment"]["state"], r["analysis"].get("worst") or "—", r["logtraffic"]] for r in bad[:40]]))
    return parts


async def _isp_sla(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    from ..isp import report as isp_report
    r = await isp_report(ch, s, start, end)
    summary["isp"] = [{"isp": i["isp_name"], "availability": i["availability"], "outages": i["outages"], "sla_met": i["sla_met"]} for i in r["isps"]]

    def d(sec):
        return f"{sec / 3600:.1f} h" if sec >= 3600 else f"{sec / 60:.0f} min" if sec else "0"
    parts.append("<h2>ISP availability vs SLA</h2>" + _table(
        ["Provider", "Sites", "Availability", "Target", "SLA", "Outages", "Downtime", "Longest", "MTTR", "Latency ms", "Loss %", "SLA breaches"],
        [[i["isp_name"], ", ".join(i["sites"]), f"{i['availability']:.3f}%" if i["availability"] is not None else "—", f"{i['target_availability']}%",
          "met" if i["sla_met"] else "MISSED", i["outages"], d(i["downtime_s"]), d(i["longest_s"]), d(i["mttr_s"]),
          i["latency_ms"] if i["latency_ms"] is not None else "—", i["packet_loss_pct"] if i["packet_loss_pct"] is not None else "—",
          i["sla_breach_total"]] for i in r["isps"]]) +
        "<h3 style='font-size:13px'>Outage log</h3>" + _table(["Provider", "Firewall", "Interface", "Start (UTC)", "End (UTC)", "Minutes"],
        [[o["isp_name"], o["firewall_name"], o["interface"], o["start"][:19].replace("T", " "), o["end"][:19].replace("T", " "),
          round(o["duration_s"] / 60, 1)] for o in r["timeline"]]))
    return parts


async def _firewall_health(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    from ..fwhealth import overview as fw_overview
    o = await fw_overview(ch, s, start, end)
    parts.append("<h2>Firewall health</h2>" + _table(
        ["Firewall", "Member", "CPU avg / max", "Memory avg / max", "Sessions max", "Reboots", "FortiAnalyzer disconnects", "Log-feed gaps now"],
        [[f["firewall_name"], m["member"], f"{m['cpu_stats']['avg']} / {m['cpu_stats']['max']}", f"{m['mem_stats']['avg']} / {m['mem_stats']['max']}",
          _fmt(m["sessions_stats"]["max"]), sum(1 for b in f["reboots"] if b["member"] == m["member"]), (f["faz"] or {}).get("disconnects", 0),
          ", ".join(f["feed_gaps"]) or "none"] for f in o["firewalls"] for m in f["members"]]))
    return parts


async def _vpn_tunnels(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    from ..vpnmon import overview as vpn_overview
    v = await vpn_overview(ch, start, end)
    parts.append("<h2>Site-to-site VPN tunnels</h2>" + _table(
        ["Firewall", "Tunnel", "Peer", "Availability", "Down events", "Downtime (min)", "Status at end"],
        [[t["firewall_name"], t["tunnel"], t["remote_ip"], f"{t['availability']:.3f}%" if t["availability"] is not None else "—", t["downs"],
          round(t["downtime_s"] / 60, 1), t["status"]] for t in v["tunnels"]]) +
        f"<p class='muted'>{_fmt(v['totals']['phase1_errors'])} IKE phase-1 failures from {v['totals']['failing_peers']} peer(s).</p>")
    return parts


async def _bgp(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    from ..bgp import audit_report as bgp_audit
    from ..bgp import report as bgp_report

    def dur(sec):
        return "—" if sec is None else f"{sec / 3600:.1f} h" if sec >= 3600 else f"{sec / 60:.0f} min"
    r = await bgp_report(ch, s, start, end, correlate=True)
    drops = [d for x in r["peers"] for d in x["down_periods"]]
    verdicts: dict = {}
    for d in drops:
        verdicts[d.get("verdict") or "unknown"] = verdicts.get(d.get("verdict") or "unknown", 0) + 1
    a = await bgp_audit(s)
    summary["bgp"] = {"neighbors": r["totals"]["peers"], "drops": r["totals"]["flaps"], "down_at_end": r["totals"]["down"]}
    parts.append("<h2>BGP neighbors</h2>" + _table(
        ["Firewall", "Neighbor", "Tunnel", "Availability", "Drops", "Downtime", "MTBF", "MTTR", "Longest", "Status at end"],
        [[x["firewall_name"], x["peer"], x["interface"] or "—", f"{x['availability']:.3f}%" if x["availability"] is not None else "—", x["flaps"],
          dur(x["downtime_s"]), dur(x["mtbf_s"]), dur(x["mttr_s"]), dur(x["longest_s"]), x["status"]] for x in r["peers"]]) +
        "<h3 style='font-size:13px'>Likely causes of neighbor drops</h3>" +
        _table(["Cause", "Drops"], [[k, v] for k, v in sorted(verdicts.items(), key=lambda kv: -kv[1])]) +
        f"<p class='muted'>Configuration audit: {', '.join(f'{v} {k}' for k, v in a['by_severity'].items()) or 'no findings'}.</p>")
    return parts


register("nms", {"policy_hygiene": _policy_hygiene, "isp_sla": _isp_sla, "firewall_health": _firewall_health, "vpn_tunnels": _vpn_tunnels, "bgp": _bgp})
register("nms", {k: _nms_parts for k in NMS_SECTIONS})   # one call renders every selected NMS section


async def _traffic_intelligence(s, ch, start, end, sections, summary) -> list[str]:
    """Application & Protocol Intelligence: top applications, top talkers, inter-VLAN and traffic detections."""
    from ..traffic import analytics as TA
    from ..traffic.query import Filters
    f = Filters(start=start, end=end)
    try:
        ov = await TA.overview(s, ch, f)
        apps = (await TA.applications(s, ch, f, None, 15, 0))["items"]
        srcs = (await TA.talkers(s, ch, f, "sources", None, 10, 0, sensitive=False))["items"]
        dsts = (await TA.talkers(s, ch, f, "destinations", None, 10, 0, sensitive=False))["items"]
        vm = (await TA.vlan_matrix(s, ch, f, 15))["items"]
    except ValueError as e:
        return [f"<h2>Application &amp; protocol intelligence</h2><p class='muted'>{h.escape(str(e))}</p>"]
    k = ov["kpis"]
    summary["traffic_intelligence"] = {x: k[x] for x in ("bytes", "flows", "sources", "destinations", "applications", "suspicious")}
    dets = (await s.execute(select(Alert.name, Alert.severity, func.count(Alert.id)).where(
        Alert.rule_key.like("traffic\\_%", escape="\\"), Alert.last_seen >= start, Alert.first_seen < end)
        .group_by(Alert.name, Alert.severity).order_by(func.count(Alert.id).desc()))).all()
    mb = lambda b: f"{b / 1e6:,.1f} MB"   # noqa: E731
    note = " (sampled telemetry: estimates)" if k["sampled_bytes"] else ""
    return ["<h2>Application &amp; protocol intelligence</h2>"
            + _table(["Traffic" + note, "Flows", "Sources", "Destinations", "Applications", "Outbound", "Inbound", "Internal", "Unknown"],
                     [[mb(k["bytes"]), _fmt(k["flows"]), _fmt(k["sources"]), _fmt(k["destinations"]), k["applications"], mb(k["outbound"]),
                       mb(k["inbound"]), mb(k["internal"]), mb(k["unknown"])]])
            + "<h3 style='font-size:13px'>Top applications</h3>"
            + _table(["Application", "Category", "Confidence", "Traffic", "Share", "Sources"],
                     [[a["app"], a["category"], a["confidence"], mb(a["bytes"]), f"{a['share']}%", a["sources"]] for a in apps])
            + "<h3 style='font-size:13px'>Top sources</h3>"
            + _table(["Source", "Device / host", "Traffic", "Peers", "Top application"],
                     [[x["ip"], x.get("device") or x.get("hostname") or "", mb(x["bytes"]), x["peers"], x["top_app"]] for x in srcs])
            + "<h3 style='font-size:13px'>Top destinations</h3>"
            + _table(["Destination", "Organisation", "Traffic", "Peers", "Top application"],
                     [[x["ip"], x.get("as_org") or x.get("device") or "", mb(x["bytes"]), x["peers"], x["top_app"]] for x in dsts])
            + "<h3 style='font-size:13px'>Inter-VLAN traffic</h3>"
            + _table(["From", "To", "Traffic", "Conversations", "Policy"],
                     [[x["src_vlan"] or "unknown", x["dst_vlan"] or "unknown", mb(x["bytes"]), x["conversations"],
                       (x["policy"] or {}).get("action", "—")] for x in vm])
            + "<h3 style='font-size:13px'>Traffic detections</h3>"
            + _table(["Detection", "Severity", "Alerts"], [[n, sev, c] for n, sev, c in dets])]


register("nms", {"traffic_intelligence": _traffic_intelligence})
