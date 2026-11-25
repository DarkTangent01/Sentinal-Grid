"""Investigation brief for one alert: what happened, why it was detected, who and what is involved, the evidence, the
possible impact, the ATT&CK context and what to check next.

It is assembled from stored records only (the alert, its rule, the matching events, the asset inventory, other alerts
about the same entity, threat-intelligence matches), and every statement about activity carries the event id and time
it comes from. It works without any AI service; when one is configured (app/ai.py explain_alert) this brief is the
model's only input, so a generated narrative can cite nothing the analyst cannot open.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import mitre, risk
from .db.models import Alert, AlertRule, Asset
from .incidents import TACTIC_TASKS, entity_of

IMPACT = {"TA0043": "Reconnaissance: no impact yet; it usually precedes an attempt against what was found.",
          "TA0001": "Initial access: an outside party may have gained a foothold on the targeted system or account.",
          "TA0002": "Execution: code may have run on the affected host.",
          "TA0003": "Persistence: access could survive password changes or reboots until the change is removed.",
          "TA0004": "Privilege escalation: an account may hold more rights than intended.",
          "TA0005": "Defence evasion: logging or controls may be weakened, so later activity may be missing from the logs.",
          "TA0006": "Credential access: one or more accounts may be compromised and usable elsewhere.",
          "TA0007": "Discovery: the source is mapping the network; follow-up connections to what it found matter most.",
          "TA0008": "Lateral movement: other internal systems reached from the source may be affected.",
          "TA0009": "Collection: data may have been gathered for later removal.",
          "TA0011": "Command and control: the host may be under remote control.",
          "TA0010": "Exfiltration: data may have left the network; quantity and destination decide the severity.",
          "TA0040": "Impact: availability or integrity of a service may be affected."}


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def _iso(v):
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace(" ", "T"))
        except ValueError:
            return v
    return _aware(v).isoformat() if v else None


async def related_events(ch, a: Alert, limit: int = 12) -> list[dict]:
    """Events inside the alert's time span that match its saved filter (the same events the alert page links to)."""
    f = a.event_filter or {}
    where = ["event_time >= {t0:DateTime64(3)}", "event_time <= {t1:DateTime64(3)}"]
    p: dict = {"t0": _aware(a.first_seen) - timedelta(minutes=1), "t1": _aware(a.last_seen) + timedelta(minutes=1)}
    cats = f.get("category")
    if cats:
        where.append("category IN {cats:Array(String)}")
        p["cats"] = list(cats) if isinstance(cats, (list, tuple)) else [str(cats)]
    for col in ("src_ip", "dst_ip", "user", "src_mac"):
        v = f.get(col) or (getattr(a, col, None) if col in ("src_ip", "dst_ip") else None)
        if v and isinstance(v, str):
            where.append(f"{col} = {{{col}:String}}")
            p[col] = v
    if len(where) == 2 + bool(cats):          # nothing identifies the entity: no evidence query rather than a random sample
        return []
    rows = await ch.aquery(
        "SELECT event_id, event_time, category, event_type, event_subtype, firewall_name, action, src_ip, dst_ip, dst_port, user, hostname, threat, "
        f"ti_match, sent_bytes, rcvd_bytes, substring(msg, 1, 300) AS msg FROM events WHERE {' AND '.join(where)} ORDER BY event_time LIMIT {int(limit)}", p)
    for r in rows:
        r["event_time"] = _iso(r["event_time"])
    return rows


async def build(s: AsyncSession, ch, a: Alert) -> dict:
    rule = (await s.execute(select(AlertRule).where(AlertRule.key == a.rule_key))).scalar_one_or_none()
    ev = a.evidence or {}
    kind, entity = entity_of(a)
    ips = [x for x in (a.src_ip, a.dst_ip) if x]
    assets = {x.ip: x for x in (await s.execute(select(Asset).where(Asset.ip.in_(ips)))).scalars()} if ips else {}
    try:
        events = await related_events(ch, a) if ch is not None else []
    except Exception:
        events = []
    since = _aware(a.first_seen) - timedelta(hours=24)
    others = []
    if entity:
        for o in (await s.execute(select(Alert).where(Alert.id != a.id, Alert.last_seen >= since).order_by(Alert.last_seen.desc()).limit(500))).scalars():
            if entity_of(o) == (kind, entity) or (a.src_ip and a.src_ip in (o.src_ip, o.dst_ip)):
                others.append({"id": o.id, "name": o.name, "severity": o.severity, "status": o.status, "last_seen": _iso(o.last_seen),
                               "techniques": (o.mitre or {}).get("techniques") or []})
    m = a.mitre or {}
    techniques = [mitre.technique(t) for t in mitre.rule_techniques(m)]
    users = sorted({str(u) for u in ([ev.get("user")] + [e.get("user") for e in events] + [(ev.get("group") or {}).get("user") if isinstance(ev.get("group"), dict) else None]) if u})
    ti = sorted({e["ti_match"] for e in events if e.get("ti_match")})
    rk = await risk.detail(s, kind, entity) if kind in ("ip", "user") and entity else None
    steps = list(ev.get("troubleshooting") or []) or [t for t in TACTIC_TASKS.get(m.get("tactic", ""), [])]
    if others:
        steps.append(f"Review the {len(others)} other alert(s) about {entity} in the previous 24 hours: together they may show a sequence")
    if ti:
        steps.append("Check the matched threat-intelligence indicator(s) and which feed lists them (a stale indicator can be marked false positive)")
    why = {"rule": a.name, "rule_key": a.rule_key, "description": (rule.description if rule else "") or "", "explanation": a.explanation,
           "metric": ev.get("metric"), "threshold": ev.get("threshold"), "confidence": ev.get("confidence"),
           "known_false_positives": ev.get("falsepositives") or [], "data_sources": ev.get("data_sources") or []}
    return {
        "alert": {"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "first_seen": _iso(a.first_seen), "last_seen": _iso(a.last_seen),
                  "event_count": a.event_count, "incident_id": a.incident_id, "base_severity": a.base_severity or a.severity},
        "what_happened": {"summary": a.explanation, "entity": {"type": kind, "value": entity},
                          "span": f"{_iso(a.first_seen)} → {_iso(a.last_seen)}", "events": a.event_count, "cite": f"alert {a.id}"},
        "why_detected": why,
        "assets": [{"ip": ip, "role": "source" if ip == a.src_ip else "destination", "known": ip in assets,
                    **({"hostname": assets[ip].hostname, "owner": assets[ip].owner, "criticality": assets[ip].criticality, "os": assets[ip].os,
                        "last_user": assets[ip].last_user} if ip in assets else {})} for ip in ips],
        "users": users,
        "evidence": {"events": events, "shown": len(events), "total": a.event_count,
                     "note": "first matching events in the alert's time span; cite as [event <event_id> @ <event_time>]" if events
                     else "no stored events could be matched to this alert (rule evaluates state, not events, or the events have expired)"},
        "threat_intel": ti,
        "impact": {"asset_criticality": a.asset_criticality or "", "tactic": m.get("tactic_name", ""),
                   "statement": IMPACT.get(m.get("tactic", ""), "Not mapped to an ATT&CK tactic: assess from the evidence."),
                   "severity_raised_by_asset": bool(a.base_severity and a.base_severity != a.severity)},
        "attack": {"tactic": m.get("tactic", ""), "tactic_name": m.get("tactic_name", ""), "techniques": techniques},
        "related_alerts": others[:20],
        "entity_risk": None if not rk else {"score": rk["score"], "level": rk["level"], "top_factors": [f["name"] for f in rk["factors"][:3]]},
        "next_steps": steps[:10],
    }
