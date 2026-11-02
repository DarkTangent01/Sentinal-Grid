"""Sentinel NMS service-check alert rules (same Detection / dedup / notification / incident pipeline as the switch
rules). All three resolve themselves when the check recovers."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from ..db.models import NmsService, Switch
from ..db.pg import session_factory
from .services import stale_after

TROUBLE = {
    "nms_service_down": ["Run the same check by hand from the NMS host (curl / nc / dig) to see the raw error",
                         "Check the service's host, its firewall rules and the path from the NMS", "Look for a deployment or restart at the same time"],
    "nms_service_degraded": ["Compare the latency with the service's history on the Service Checks page", "Check load on the host and the network path"],
    "snmp_trap": ["Read the trap's varbinds on the SNMP → Traps page", "Check the device log at the same time (show logging / show log messages)"],
    "nms_cert_expiry": ["Renew the certificate and deploy it with its full chain", "Check that automatic renewal (ACME / internal CA) is still running"],
}

DEFAULT_RULES = [
    {"key": "nms_service_down", "name": "Service check failing", "severity": "high", "mitre": {},
     "description": "A TCP / HTTP / DNS / TLS service check failed for several consecutive runs.", "params": {"min_failures": 2}},
    {"key": "nms_service_degraded", "name": "Service check degraded", "severity": "low", "mitre": {},
     "description": "A service check answers, but slower than its latency threshold or with a warning, for several minutes.",
     "params": {"min_minutes": 10}},
    {"key": "snmp_trap", "name": "SNMP trap from a network device", "severity": "medium", "mitre": {},
     "description": "A device sent an SNMP notification at or above the minimum severity (environment, power, fan, BGP, cold start …). "
                    "Paired notifications (jnxFanFailure / jnxFanOK, bgpBackwardTransition / bgpEstablished) clear the alert; others clear after "
                    "the window. linkDown is excluded by default: switch_port_down already covers port state from polling.",
     "params": {"window_minutes": 60, "min_severity": "medium", "exclude_oids": ["1.3.6.1.6.3.1.1.5.3"]}},
    {"key": "nms_cert_expiry", "name": "TLS certificate expiring", "severity": "medium", "mitre": {},
     "description": "A TLS check's certificate expires within its warning period (high within 7 days or once expired).", "params": {"critical_days": 7}},
]
AUTO_RESOLVE = {r["key"] for r in DEFAULT_RULES}


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


async def _context():
    async with session_factory()() as s:
        svcs = (await s.execute(select(NmsService).where(NmsService.enabled.is_(True)))).scalars().all()
        sws = {x.id: x for x in (await s.execute(select(Switch))).scalars()}
    return svcs, sws


def _det(svc: NmsService, sw: Switch | None, key: str, rule: str, explanation: str, now: datetime, *, severity=None, extra=None):
    from ..alerts.engine import Detection
    site = svc.site or (sw.site if sw else "")
    ev = {"service": svc.name, "service_id": svc.id, "kind": svc.kind, "target": svc.target, "port": svc.port, "state": svc.state,
          "message": svc.last_message, "latency_ms": svc.last_latency_ms, "fail_streak": svc.fail_streak, "site": site,
          "switch_id": sw.id if sw else None, "switch": sw.name if sw else None, "detected_at": now.isoformat(),
          "troubleshooting": TROUBLE.get(rule, []), "link": f"/nms/services?id={svc.id}", **(extra or {})}
    return Detection(group_key=key, count=max(1, svc.fail_streak), first_seen=_aware(svc.state_since) or now, last_seen=now,
                     explanation=explanation, dst_ip=None, firewall_ids=[], sites=[site] if site else [], evidence=ev, event_filter={},
                     severity=severity)


def _fresh(svc: NmsService, now) -> bool:
    last = _aware(svc.last_check_at)
    return bool(last and now - last <= stale_after(svc))


async def rule_nms_service_down(ch, now, p):
    svcs, sws = await _context()
    n = int(p.get("min_failures", 2))
    return [_det(svc, sws.get(svc.switch_id or 0), f"{svc.id}:{(_aware(svc.state_since) or now):%Y%m%d%H%M%S}", "nms_service_down",
                 f"{svc.name} ({svc.kind} {svc.target}{':' + str(svc.port) if svc.port else ''}) failed {svc.fail_streak} times in a row: "
                 f"{svc.last_message}", now)
            for svc in svcs if _fresh(svc, now) and svc.state == "critical" and svc.fail_streak >= n and not _expired_only(svc, now)]


def _expired_only(svc: NmsService, now) -> bool:
    """A TLS check that is critical only because the certificate expired belongs to nms_cert_expiry, not to the down rule."""
    exp = _aware(svc.cert_expires_at)
    return svc.kind == "tls" and exp is not None and exp < now and (svc.last_message or "").startswith("certificate expired")


async def rule_nms_service_degraded(ch, now, p):
    svcs, sws = await _context()
    mins = float(p.get("min_minutes", 10))
    out = []
    for svc in svcs:
        since = _aware(svc.state_since)
        if svc.kind == "tls" or not _fresh(svc, now) or svc.state != "warning" or not since or (now - since).total_seconds() < mins * 60:
            continue
        out.append(_det(svc, sws.get(svc.switch_id or 0), f"{svc.id}:{since:%Y%m%d%H%M%S}", "nms_service_degraded",
                        f"{svc.name}: {svc.last_message} (for {(now - since).total_seconds() / 60:.0f} min)", now))
    return out


async def rule_nms_cert_expiry(ch, now, p):
    svcs, sws = await _context()
    crit = float(p.get("critical_days", 7))
    out = []
    for svc in svcs:
        exp = _aware(svc.cert_expires_at)
        if svc.kind != "tls" or not exp or not _fresh(svc, now):
            continue
        days = (exp - now).total_seconds() / 86400
        if days >= (svc.cert_warn_days or 21):
            continue
        out.append(_det(svc, sws.get(svc.switch_id or 0), f"{svc.id}:{exp:%Y%m%d}", "nms_cert_expiry",
                        f"{svc.name}: TLS certificate of {svc.target}:{svc.port} " + (f"expired {abs(days):.0f} day(s) ago" if days < 0 else
                                                                                       f"expires in {days:.0f} day(s)") + f" ({exp:%Y-%m-%d})",
                        now, severity="high" if days < crit else None, extra={"cert_expires_at": exp.isoformat(), "days_left": round(days, 1)}))
    return out


SEV = ["informational", "low", "medium", "high", "critical"]


async def rule_snmp_trap(ch, now, p):
    from datetime import timedelta

    from ..snmp_traps import CLEARED_BY, CLEARS
    from ..switches.alerts import _context as sw_context, _det as sw_det
    t0 = now - timedelta(minutes=float(p.get("window_minutes", 60)))
    rows = await ch.aquery("SELECT ts, switch_id, trap_oid, trap_name, severity, component, summary, repeats FROM snmp_traps "
                           "WHERE ts >= {t0:DateTime64(3)} ORDER BY ts", {"t0": t0})
    floor = SEV.index(p.get("min_severity", "medium")) if p.get("min_severity") in SEV else 2
    skip = set(p.get("exclude_oids") or [])
    latest: dict[tuple, dict] = {}
    for r in rows:
        fam = CLEARED_BY.get(r["trap_oid"], r["trap_oid"])     # a clearing notification lands on its raising one's key
        latest[(int(r["switch_id"]), fam, r["component"])] = r
    sws, bs = await sw_context()
    by = {x.id: x for x in sws}
    out = []
    for (sid, fam, comp), r in latest.items():
        sw = by.get(sid)
        if sw is None or fam in skip or r["trap_oid"] in CLEARED_BY:   # latest is the clearing notification → condition cleared
            continue
        if r["severity"] not in SEV or SEV.index(r["severity"]) < floor:
            continue
        ts = r["ts"] if isinstance(r["ts"], datetime) else datetime.fromisoformat(str(r["ts"]))
        ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        out.append(sw_det(sw, bs, f"{sid}:{fam}:{comp}", "snmp_trap", f"{sw.name}: {r['summary']} ({r['trap_name']})", first=ts, last=ts,
                          count=1 + int(r["repeats"] or 0), component=comp or r["trap_name"], metric=r["trap_name"], severity=r["severity"],
                          extra={"trap_oid": r["trap_oid"], "clears_with": CLEARS.get(fam)}))
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}
