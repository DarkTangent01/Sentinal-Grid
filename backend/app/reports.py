"""Scheduled HTML reports (printable; emailed through notification channels)."""
from __future__ import annotations

import html as h
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .analytics import queries as Q
from .analytics.filters import EventFilter
from .analytics.ngen import ti_summary, vpn_summary
from .compliance import compliance_status
from .db.ch import ClickHouse
from .db.models import Alert, Incident, ReportDefinition, ReportRun

SECTIONS = ["summary", "alerts", "incidents", "threats", "threat_intel", "vpn", "policy_hygiene", "compliance", "isp_sla",
            "firewall_health", "vpn_tunnels", "bgp"]


def _fmt(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "<p class='muted'>No data for this period.</p>"
    head = "".join(f"<th>{h.escape(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{h.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


async def generate(s: AsyncSession, ch: ClickHouse, name: str, start: datetime, end: datetime, sections: list[str]) -> tuple[str, dict]:
    f = EventFilter(start=start, end=end)
    parts, summary = [], {}
    if "summary" in sections:
        k = await Q.kpis(ch, f)
        summary["kpis"] = {x: k.get(x) for x in ("traffic_events", "denied_events", "dns_queries", "url_blocks", "security_events", "unique_src")}
        parts.append("<h2>Summary</h2>" + _table(["Metric", "Value"], [
            ["Traffic events", _fmt(k.get("traffic_events"))], ["Denied events", _fmt(k.get("denied_events"))],
            ["Data transferred (bytes)", _fmt(k.get("bytes_total"))], ["DNS queries", _fmt(k.get("dns_queries"))],
            ["URL filtering blocks", _fmt(k.get("url_blocks"))], ["Security events", _fmt(k.get("security_events"))],
            ["Unique source IPs", _fmt(k.get("unique_src"))]]))
    if "alerts" in sections:
        rows = (await s.execute(select(Alert.rule_key, Alert.name, Alert.severity, func.count(Alert.id)).where(
            Alert.last_seen >= start, Alert.first_seen < end).group_by(Alert.rule_key, Alert.name, Alert.severity)
            .order_by(func.count(Alert.id).desc()).limit(25))).all()
        summary["alerts"] = sum(r[3] for r in rows)
        parts.append(f"<h2>Alerts ({summary['alerts']})</h2>" + _table(["Detection", "Severity", "Alerts"], [[r[1], r[2], r[3]] for r in rows]))
    if "incidents" in sections:
        incs = (await s.execute(select(Incident).where(Incident.last_seen >= start, Incident.first_seen < end)
                                .order_by(Incident.score.desc()).limit(25))).scalars().all()
        closed = [i for i in incs if i.resolved_at]
        mttr = (sum(((i.resolved_at - i.created_at).total_seconds() for i in closed), 0) / len(closed) / 3600) if closed else None
        summary["incidents"] = {"total": len(incs), "closed": len(closed), "mttr_hours": round(mttr, 1) if mttr else None}
        parts.append(f"<h2>Incidents ({len(incs)}, closed {len(closed)}{f', MTTR {mttr:.1f} h' if mttr else ''})</h2>" +
                     _table(["#", "Title", "Severity", "Status", "Alerts", "Tactics"],
                            [[i.id, i.title, i.severity, i.status, i.alert_count, ", ".join(i.tactics)] for i in incs]))
    if "threats" in sections:
        sec = await Q.security_summary(ch, f)
        parts.append("<h2>Top threats / signatures</h2>" + _table(["Threat", "Type", "Severity", "Events", "Sources"],
                     [[r["threat"], r["event_subtype"], r["severity"], _fmt(r["events"]), _fmt(r["sources"])] for r in sec["top_threats"][:15]]))
    if "threat_intel" in sections:
        ti = await ti_summary(ch, f)
        summary["ti_events"] = ti["totals"].get("events")
        parts.append(f"<h2>Threat-intel matches ({_fmt(ti['totals'].get('events', 0))} events)</h2>" + _table(
            ["Indicator", "Feed", "Category", "Events", "Hosts"],
            [[r["indicator"], r["feed"], r["category"], _fmt(r["events"]), _fmt(r["hosts"])] for r in ti["indicators"][:20]]))
    if "vpn" in sections:
        v = await vpn_summary(ch, f)
        t = v["totals"]
        parts.append("<h2>VPN</h2>" + _table(["Logins", "Failures", "Users", "Impossible travel"],
                     [[_fmt(t.get("logins")), _fmt(t.get("failures")), _fmt(t.get("users")), len(v["impossible_travel"])]]))
    if "policy_hygiene" in sections:
        from .api.policies import _rows
        try:
            rows = await _rows(s, ch, 30)
        except Exception:
            rows = []
        bad = [r for r in rows if r["assessment"]["state"] in ("potentially_unused", "no_observed_hits") or r["analysis"].get("worst")]
        parts.append(f"<h2>Firewall policy hygiene (30-day window, {len(rows)} policies)</h2>" + _table(
            ["Firewall", "Policy", "Name", "Usage", "Shadow", "Logging"],
            [[r["firewall"], r["policyid"], r["name"], r["assessment"]["state"], r["analysis"].get("worst") or "—", r["logtraffic"]] for r in bad[:40]]))
    if "compliance" in sections:
        c = await compliance_status(s)
        summary["compliance"] = c["counts"]
        parts.append("<h2>Compliance evidence</h2>" + _table(["Framework", "Control", "Status"],
                     [[fw["framework"], f"{x['id']} {x['title']}", x["status"]] for fw in c["frameworks"] for x in fw["controls"]]) +
                     f"<p class='muted'>{h.escape(c['disclaimer'])}</p>")
    if "isp_sla" in sections:
        from .isp import report as isp_report
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
    if "firewall_health" in sections:
        from .fwhealth import overview as fw_overview
        o = await fw_overview(ch, s, start, end)
        parts.append("<h2>Firewall health</h2>" + _table(
            ["Firewall", "Member", "CPU avg / max", "Memory avg / max", "Sessions max", "Reboots", "FortiAnalyzer disconnects", "Log-feed gaps now"],
            [[f["firewall_name"], m["member"], f"{m['cpu_stats']['avg']} / {m['cpu_stats']['max']}", f"{m['mem_stats']['avg']} / {m['mem_stats']['max']}",
              _fmt(m["sessions_stats"]["max"]), sum(1 for b in f["reboots"] if b["member"] == m["member"]), (f["faz"] or {}).get("disconnects", 0),
              ", ".join(f["feed_gaps"]) or "none"] for f in o["firewalls"] for m in f["members"]]))
    if "vpn_tunnels" in sections:
        from .vpnmon import overview as vpn_overview
        v = await vpn_overview(ch, start, end)
        parts.append("<h2>Site-to-site VPN tunnels</h2>" + _table(
            ["Firewall", "Tunnel", "Peer", "Availability", "Down events", "Downtime (min)", "Status at end"],
            [[t["firewall_name"], t["tunnel"], t["remote_ip"], f"{t['availability']:.3f}%" if t["availability"] is not None else "—", t["downs"],
              round(t["downtime_s"] / 60, 1), t["status"]] for t in v["tunnels"]]) +
            f"<p class='muted'>{_fmt(v['totals']['phase1_errors'])} IKE phase-1 failures from {v['totals']['failing_peers']} peer(s).</p>")
    if "bgp" in sections:
        from .bgp import report as bgp_report
        from .bgp import audit_report as bgp_audit

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
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{h.escape(name)}</title><style>
body{{font:13px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;margin:24px;max-width:1000px}}
h1{{font-size:20px;margin:0}} h2{{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #e2e8f0;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid #eef2f6;vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;color:#475569}} .muted{{color:#64748b}} @media print{{body{{margin:0}}}}
</style></head><body><h1>{h.escape(name)}</h1><p class="muted">Sentinel Grid report · {start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} UTC ·
generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>{''.join(parts)}</body></html>"""
    return doc, summary


async def run_definition(s: AsyncSession, ch: ClickHouse, d: ReportDefinition, now: datetime | None = None) -> ReportRun:
    now = now or datetime.now(timezone.utc)
    start, end = period_window(d.period, now)
    html_doc, summary = await generate(s, ch, d.name, start, end, d.sections or SECTIONS)
    run = ReportRun(definition_id=d.id, name=d.name, generated_at=now, period_start=start, period_end=end, html=html_doc, summary=summary)
    s.add(run)
    d.last_run = now
    await s.flush()
    if d.channel_ids:
        from .notify import _link, enqueue
        await enqueue(s, "report.ready", {"title": f"Report: {d.name}", "subject": f"Sentinel Grid report: {d.name}",
                                          "text": f"{d.period.title()} report generated.", "html": html_doc,
                                          "url": _link(f"/api/reports/runs/{run.id}.html")},
                      severity="informational", dedupe_key=f"report:{run.id}", channel_ids=list(d.channel_ids))
    await s.commit()
    return run


def period_window(period: str, now: datetime) -> tuple[datetime, datetime]:
    """daily / weekly: the trailing 1 or 7 days. monthly: the previous calendar month (UTC), as SLA reports need."""
    if period == "monthly":
        end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (end - timedelta(days=1)).replace(day=1)
        return start, end
    return now - timedelta(days=7 if period == "weekly" else 1), now


def is_due(d: ReportDefinition, now: datetime) -> bool:
    try:
        local = now.astimezone(ZoneInfo(d.tz or "UTC"))
    except (KeyError, ValueError):
        local = now
    if local.hour != d.send_hour or (d.period == "monthly" and local.day != 1):
        return False
    last = d.last_run if d.last_run is None or d.last_run.tzinfo else d.last_run.replace(tzinfo=timezone.utc)
    gap = timedelta(days={"weekly": 7, "monthly": 27}.get(d.period, 1)) - timedelta(hours=1)
    return last is None or now - last >= gap


async def run_due(s: AsyncSession, ch: ClickHouse, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    out = {}
    for d in (await s.execute(select(ReportDefinition).where(ReportDefinition.enabled.is_(True)))).scalars().all():
        if is_due(d, now):
            out[d.name] = (await run_definition(s, ch, d, now)).id
    return out
