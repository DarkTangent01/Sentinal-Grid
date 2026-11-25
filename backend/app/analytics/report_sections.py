"""Sentinel Grid report sections (security summary, alerts, incidents, threats, threat intel, VPN, compliance),
registered with the report framework (app/reports.py)."""
from __future__ import annotations

import html as h

from sqlalchemy import func, select

from ..compliance import compliance_status
from ..db.models import Alert, Incident
from ..platform.eventquery import EventFilter
from ..reports import _fmt, _table, register
from . import queries as Q
from .ngen import ti_summary, vpn_summary


async def _summary(s, ch, start, end, sections, summary) -> list[str]:
    f = EventFilter(start=start, end=end)
    parts: list[str] = []
    k = await Q.kpis(ch, f)
    summary["kpis"] = {x: k.get(x) for x in ("traffic_events", "denied_events", "dns_queries", "url_blocks", "security_events", "unique_src")}
    parts.append("<h2>Summary</h2>" + _table(["Metric", "Value"], [
        ["Traffic events", _fmt(k.get("traffic_events"))], ["Denied events", _fmt(k.get("denied_events"))],
        ["Data transferred (bytes)", _fmt(k.get("bytes_total"))], ["DNS queries", _fmt(k.get("dns_queries"))],
        ["URL filtering blocks", _fmt(k.get("url_blocks"))], ["Security events", _fmt(k.get("security_events"))],
        ["Unique source IPs", _fmt(k.get("unique_src"))]]))
    return parts


async def _alerts(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    rows = (await s.execute(select(Alert.rule_key, Alert.name, Alert.severity, func.count(Alert.id)).where(
        Alert.last_seen >= start, Alert.first_seen < end).group_by(Alert.rule_key, Alert.name, Alert.severity)
        .order_by(func.count(Alert.id).desc()).limit(25))).all()
    summary["alerts"] = sum(r[3] for r in rows)
    parts.append(f"<h2>Alerts ({summary['alerts']})</h2>" + _table(["Detection", "Severity", "Alerts"], [[r[1], r[2], r[3]] for r in rows]))
    return parts


async def _incidents(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    incs = (await s.execute(select(Incident).where(Incident.category == "security", Incident.last_seen >= start, Incident.first_seen < end)
                            .order_by(Incident.score.desc()).limit(25))).scalars().all()
    closed = [i for i in incs if i.resolved_at]
    mttr = (sum(((i.resolved_at - i.created_at).total_seconds() for i in closed), 0) / len(closed) / 3600) if closed else None
    summary["incidents"] = {"total": len(incs), "closed": len(closed), "mttr_hours": round(mttr, 1) if mttr else None}
    parts.append(f"<h2>Incidents ({len(incs)}, closed {len(closed)}{f', MTTR {mttr:.1f} h' if mttr else ''})</h2>" +
                 _table(["#", "Title", "Severity", "Status", "Alerts", "Tactics"],
                        [[i.id, i.title, i.severity, i.status, i.alert_count, ", ".join(i.tactics)] for i in incs]))
    return parts


async def _threats(s, ch, start, end, sections, summary) -> list[str]:
    f = EventFilter(start=start, end=end)
    parts: list[str] = []
    sec = await Q.security_summary(ch, f)
    parts.append("<h2>Top threats / signatures</h2>" + _table(["Threat", "Type", "Severity", "Events", "Sources"],
                 [[r["threat"], r["event_subtype"], r["severity"], _fmt(r["events"]), _fmt(r["sources"])] for r in sec["top_threats"][:15]]))
    return parts


async def _threat_intel(s, ch, start, end, sections, summary) -> list[str]:
    f = EventFilter(start=start, end=end)
    parts: list[str] = []
    ti = await ti_summary(ch, f)
    summary["ti_events"] = ti["totals"].get("events")
    parts.append(f"<h2>Threat-intel matches ({_fmt(ti['totals'].get('events', 0))} events)</h2>" + _table(
        ["Indicator", "Feed", "Category", "Events", "Hosts"],
        [[r["indicator"], r["feed"], r["category"], _fmt(r["events"]), _fmt(r["hosts"])] for r in ti["indicators"][:20]]))
    return parts


async def _vpn(s, ch, start, end, sections, summary) -> list[str]:
    f = EventFilter(start=start, end=end)
    parts: list[str] = []
    v = await vpn_summary(ch, f)
    t = v["totals"]
    parts.append("<h2>VPN</h2>" + _table(["Logins", "Failures", "Users", "Impossible travel"],
                 [[_fmt(t.get("logins")), _fmt(t.get("failures")), _fmt(t.get("users")), len(v["impossible_travel"])]]))
    return parts


async def _compliance(s, ch, start, end, sections, summary) -> list[str]:
    parts: list[str] = []
    c = await compliance_status(s)
    summary["compliance"] = c["counts"]
    parts.append("<h2>Compliance evidence</h2>" + _table(["Framework", "Control", "Status"],
                 [[fw["framework"], f"{x['id']} {x['title']}", x["status"]] for fw in c["frameworks"] for x in fw["controls"]]) +
                 f"<p class='muted'>{h.escape(c['disclaimer'])}</p>")
    return parts


register("grid", {"summary": _summary, "alerts": _alerts, "incidents": _incidents, "threats": _threats, "threat_intel": _threat_intel, "vpn": _vpn, "compliance": _compliance})
