"""Sentinel NMS alert rules, registered with the alert framework (alerts/engine.py).

Firewall health, WAN / ISP, ICMP, IPsec, BGP and IaC-drift rules defined here, plus the rule sets of the NMS modules
(switches, TACACS+, WAN, wireless, NMS analytics, anomalies, device configuration). New alerts of devices covered by
an NMS maintenance window are held back; stateful conditions resolve themselves and notify recovery.
"""
import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..configs import alerts as _configs
from ..nms import alerts as _nms
from ..nms import anomaly as _anomaly
from ..switches import alerts as _switches
from ..tacacs import alerts as _tacacs
from ..traffic import detections as _traffic
from .. import wan_alerts as _wan
from ..wireless import alerts as _wireless
from . import engine
from .engine import M, Detection, _dt

log = logging.getLogger("alerts")

DEFAULT_RULES = [
    {"key": "risky_config_change", "name": "Risky firewall configuration change", "severity": "high", "mitre": M("TA0005", "T1562.004"),
     "description": "Configuration drift introduced a risky setting (any/any accept policy, admin access on WAN, insecure protocols, new admin).",
     "params": {}},
    {"key": "isp_outage", "name": "ISP / WAN link down", "severity": "medium", "mitre": {},
     "description": "Every SD-WAN health check on a WAN link failed at the same time (provider outage), for at least the configured minutes.",
     "params": {"window_minutes": 15, "min_outage_minutes": 2}},
    {"key": "fw_resource_high", "name": "Firewall CPU / memory high", "severity": "medium", "mitre": {},
     "description": "A firewall (HA member) stayed above the CPU or memory threshold for several consecutive performance samples.",
     "params": {"window_minutes": 20, "cpu_pct": 85, "mem_pct": 85, "min_samples": 3}},
    {"key": "fw_reboot", "name": "Firewall rebooted", "severity": "high", "mitre": {},
     "description": "System uptime went backwards between performance samples: the firewall or an HA member restarted.",
     "params": {"window_minutes": 60}},
    {"key": "log_feed_gap", "name": "Firewall log feed stopped", "severity": "medium", "mitre": M("TA0005", "T1562.006"),
     "description": "A firewall stopped sending a log category it normally sends (logging disabled, syslog filter changed, or link loss).",
     "params": {"silent_minutes": 20}},
    {"key": "icmp_down", "name": "Monitored public IP unreachable (ICMP)", "severity": "medium", "mitre": {},
     "description": "An ICMP-monitored address (ISP WAN IP, gateway, upstream) is DOWN after its consecutive-failure threshold.",
     "params": {"min_down_minutes": 1}},
    {"key": "vpn_tunnel_down", "name": "Site-to-site VPN tunnel down", "severity": "medium", "mitre": {},
     "description": "An IPsec site-to-site tunnel went down and has not come back for the configured minutes.",
     "params": {"window_minutes": 60, "min_down_minutes": 5}},
    {"key": "iac_drift", "name": "Firewall configuration drifted from the approved IaC state", "severity": "high",
     "mitre": M("TA0005", "T1562.004"),
     "description": "A scheduled or on-demand IaC drift check found the live firewall configuration differing from the approved desired "
                    "state (manual GUI/CLI change, unexpected policy, routing or admin-access change).",
     "params": {"interval_minutes": 5, "window_minutes": 15, "min_severity": "medium"}},
    {"key": "bgp_peer_down", "name": "BGP neighbor down", "severity": "high", "mitre": {},
     "description": "A BGP neighbor left the Established state (from router logs or API polling) and stayed down for the configured minutes.",
     "params": {"interval_minutes": 2, "window_minutes": 60, "min_down_minutes": 2}},
    {"key": "bgp_peer_flap", "name": "BGP neighbor flapping", "severity": "medium", "mitre": {},
     "description": "A BGP neighbor went down repeatedly in a short window: unstable link, hold-timer expiries or a mismatched peer.",
     "params": {"interval_minutes": 5, "window_minutes": 60, "min_flaps": 3}},
    {"key": "bgp_route_withdrawals", "name": "BGP route withdrawal burst", "severity": "medium", "mitre": {},
     "description": "Many prefixes were withdrawn for one neighbor in a short window: lost reachability or an upstream routing change.",
     "params": {"interval_minutes": 5, "window_minutes": 15, "min_withdrawals": 50}},
    {"key": "bgp_prefix_anomaly", "name": "BGP prefix count far from baseline", "severity": "medium", "mitre": {},
     "description": "An established neighbor sends far fewer (partial table loss) or far more (possible leak) prefixes than its 7-day median.",
     "params": {"interval_minutes": 10, "deviation_pct": 30, "min_abs": 5, "min_samples": 30}},
    {"key": "bgp_route_leak", "name": "BGP route leak / hijack signal", "severity": "high", "mitre": M("TA0040", "T1565"),
     "description": "A neighbor announced a burst of never-seen prefixes, a more-specific of this firewall's own networks, a bogon, a public "
                    "prefix over an internal session, or the default route changed; or a new neighbor appeared.",
     "params": {"interval_minutes": 5, "window_minutes": 15,
                "kinds": ["leak_suspect", "more_specific", "bogon_prefix", "default_route", "new_peer", "public_via_internal"]}},
    {"key": "bgp_critical_prefix", "name": "Critical prefix withdrawn or rerouted", "severity": "high", "mitre": {},
     "description": "A prefix in the BGP critical prefix list (BGP page) was withdrawn, left the routing table, or moved to "
                    "another neighbor / tunnel.",
     "params": {"interval_minutes": 2, "window_minutes": 10, "watchlist": "bgp_critical_prefixes"}},
]


async def rule_risky_config_change(ch, now, p):
    return []  # detections are produced by the config-drift collector (app/drift.py)


async def rule_isp_outage(ch, now, p):
    """Full outages on WAN links (see app/isp.py) overlapping the window. Group key = link, so one alert per link
    tracks the current outage; an outage that starts after the alert was resolved opens a new one."""
    from ..db.pg import session_factory
    from ..isp import analyze_link, configs, load
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    links = await load(ch, t0 - timedelta(hours=1), now)
    async with session_factory()() as s:
        cfgs = await configs(s)
    out = []
    for key, lk in links.items():
        cfg = cfgs.get(key)
        if cfg and cfg.hidden:
            continue
        r = analyze_link(lk, cfg, t0 - timedelta(hours=1), now, min_outage=int(p.get("min_outage_minutes", 2)) * 60)
        recent = [(a, b) for a, b in r["_outages"] if b >= t0]
        if not recent:
            continue
        a, b = recent[-1]
        ongoing = r["status"] == "down"
        mins = round((b - a).total_seconds() / 60, 1)
        out.append(Detection(
            group_key=r["key"], count=len(recent), first_seen=a, last_seen=b, firewall_ids=[lk.firewall_id],
            explanation=(f"{(cfg.isp_name or cfg.as_org) + ' ' if cfg and (cfg.isp_name or cfg.as_org) else ''}WAN link {lk.interface} on {lk.firewall_name}{f' (gateway {lk.gateway})' if lk.gateway else ''} "
                         f"{'is down' if ongoing else 'was down'} for {mins} min: all {len(r['outage_checks'])} health checks failed "
                         f"({', '.join(r['outage_checks'][:5])})."),
            evidence={"interface": lk.interface, "gateway": lk.gateway, "start": a.isoformat(), "end": b.isoformat(), "ongoing": ongoing,
                      "checks": r["outage_checks"]},
            event_filter={"category": ["system"], "event_subtype": "sdwan", "q": f'interface="{lk.interface}"'}))
    return out


async def rule_icmp_down(ch, now, p):
    """Targets currently DOWN (state kept by the ICMP prober). One alert per outage: the group key includes the time
    the target went down, so a later outage opens a new alert."""
    from ..db.models import IcmpTarget
    from ..db.pg import session_factory
    async with session_factory()() as s:
        rows = (await s.execute(select(IcmpTarget).where(IcmpTarget.enabled.is_(True), IcmpTarget.state == "down"))).scalars().all()
    out = []
    for t in rows:
        since = _dt(t.state_since) if t.state_since else now
        mins = (now - since).total_seconds() / 60
        if mins < float(p.get("min_down_minutes", 1)):
            continue
        out.append(Detection(group_key=f"{t.id}:{since:%Y%m%d%H%M%S}", count=t.fail_streak, first_seen=since, last_seen=now,
                             dst_ip=t.address if t.address.replace(".", "").replace(":", "").isalnum() else None,
                             explanation=f"{t.name} ({t.address}) has not answered ICMP for {mins:.0f} min "
                                         f"({t.fail_streak} consecutive failed checks of {t.probes} probes).",
                             evidence={"address": t.address, "down_since": since.isoformat(), "failed_checks": t.fail_streak},
                             event_filter={}))
    return out


async def rule_fw_resource_high(ch, now, p):
    from ..fwhealth import perf_samples
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    by: dict = {}
    for r in await perf_samples(ch, t0, now):
        by.setdefault((r["firewall_id"], r["member"]), []).append(r)
    out = []
    for (fid, member), rs in by.items():
        hot = [r for r in rs if (r["cpu"] or 0) >= float(p["cpu_pct"]) or (r["mem"] or 0) >= float(p["mem_pct"])]
        if len(hot) < int(p["min_samples"]) or rs[-1] not in hot:
            continue
        last = rs[-1]
        out.append(Detection(group_key=f"{fid}:{member}", count=len(hot), first_seen=hot[0]["t"], last_seen=last["t"], firewall_ids=[fid],
                             explanation=f"{member}: CPU {last['cpu'] or 0:.0f}% / memory {last['mem'] or 0:.0f}% ({len(hot)} of {len(rs)} samples over the "
                                         f"threshold in {p['window_minutes']} min; {int(last['sessions'] or 0):,} sessions).",
                             evidence={"cpu": last["cpu"], "mem": last["mem"], "sessions": last["sessions"]},
                             event_filter={"category": ["system"], "q": "Performance statistics"}))
    return out


async def rule_fw_reboot(ch, now, p):
    from ..fwhealth import perf_samples, reboots
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    out = []
    for b in reboots(await perf_samples(ch, t0 - timedelta(hours=2), now)):
        boot = _dt(b["boot_time"])
        if _dt(b["detected_at"]) < t0:
            continue
        out.append(Detection(group_key=f"{b['firewall_id']}:{b['member']}:{boot:%Y%m%d%H%M}", count=1, first_seen=boot, last_seen=_dt(b["detected_at"]),
                             firewall_ids=[b["firewall_id"]], explanation=f"{b['member']} restarted around {boot:%Y-%m-%d %H:%M} UTC "
                             f"(uptime before restart {b['previous_uptime_s'] // 86400} days).", evidence=b,
                             event_filter={"category": ["system"], "start": boot.isoformat()}))
    return out


async def rule_log_feed_gap(ch, now, p):
    from ..fwhealth import feed_status
    out = []
    for f in await feed_status(ch, now, int(p["silent_minutes"])):
        if not f["gap"]:
            continue
        last = _dt(f["last_event"])
        out.append(Detection(group_key=f"{f['firewall_id']}:{f['category']}", count=1, first_seen=last, last_seen=now, firewall_ids=[f["firewall_id"]],
                             explanation=f"No {f['category']} logs for {f['silent_minutes']:.0f} min from firewall #{f['firewall_id']} "
                                         f"(it sent {f['events_24h']:,} in the last 24 h).", evidence=f,
                             event_filter={"category": [f["category"]], "firewall_id": [f["firewall_id"]]}))
    return out


async def rule_vpn_tunnel_down(ch, now, p):
    from ..vpnmon import tunnels
    t0 = now - timedelta(minutes=int(p["window_minutes"]))
    out = []
    for t in (await tunnels(ch, t0, now))["tunnels"]:
        for d in t["down_periods"]:
            if d["duration_s"] < int(p["min_down_minutes"]) * 60:
                continue
            a = _dt(d["start"])
            ongoing = t["status"] == "down"
            out.append(Detection(group_key=f"{t['firewall_id']}:{t['tunnel']}", count=1, first_seen=a, last_seen=_dt(d["end"]),
                                 firewall_ids=[t["firewall_id"]], dst_ip=t["remote_ip"] or None,
                                 explanation=f"IPsec tunnel {t['tunnel']} on {t['firewall_name']} (peer {t['remote_ip']}) "
                                             f"{'is down' if ongoing else 'was down'} for {d['duration_s'] / 60:.0f} min.",
                                 evidence={**d, "tunnel": t["tunnel"], "peer": t["remote_ip"]},
                                 event_filter={"category": ["system"], "q": f'vpntunnel="{t["tunnel"]}"'}))
    return out


async def rule_iac_drift(ch, now, p):
    from ..db.models import Firewall, IacDrift
    from ..db.pg import session_factory
    from ..iac.diff import SEV
    floor = SEV.index(p.get("min_severity", "medium"))
    out = []
    async with session_factory()() as s:
        rows = (await s.execute(select(IacDrift, Firewall.name).join(Firewall, Firewall.id == IacDrift.firewall_id).where(
            IacDrift.checked_at >= now - timedelta(minutes=int(p["window_minutes"])), IacDrift.status == "drift"))).all()
    for r, name in rows:
        hits = [f for f in r.findings if SEV.index(f["severity"]) >= floor]
        if not hits:
            continue
        top = max(hits, key=lambda f: SEV.index(f["severity"]))
        out.append(Detection(group_key=f"iac-drift:{r.firewall_id}", count=len(hits), first_seen=_dt(r.checked_at), last_seen=_dt(r.checked_at),
                             firewall_ids=[r.firewall_id], severity="critical" if top["severity"] == "critical" else None,
                             explanation=f"{name} differs from its approved IaC configuration in {len(hits)} place(s); most severe: {top['explanation']}",
                             evidence={"drift_id": r.id, "counts": r.counts, "findings": hits[:20]},
                             event_filter={"category": ["system"], "firewall_id": [r.firewall_id]}))
    return out


async def _bgp_report(ch, now, minutes, correlate=False):
    from ..bgp import report
    from ..db.pg import session_factory
    async with session_factory()() as s:
        return await report(ch, s, now - timedelta(minutes=int(minutes)), now, correlate=correlate)


async def _bgp_events(ch, now, minutes, kinds):
    from ..bgp import _window_events
    from ..db.pg import session_factory
    async with session_factory()() as s:
        evs, _ = await _window_events(ch, s, now - timedelta(minutes=int(minutes)), now, None)
    return [e for e in evs if e["kind"] in kinds]


async def rule_bgp_prefix_anomaly(ch, now, p):
    from ..bgp_analysis import is_anomalous
    out = []
    for x in (await _bgp_report(ch, now, 60))["peers"]:
        b = x["baseline"]
        if x["status"] != "up" or not is_anomalous(b, int(p["min_samples"]), float(p["deviation_pct"]), int(p["min_abs"])):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=1, first_seen=now, last_seen=now, firewall_ids=[x["firewall_id"]],
                             dst_ip=x["peer"], explanation=f"BGP neighbor {x['peer']} on {x['firewall_name']} sends {b['current']} prefixes; its 7-day "
                             f"median is {b['median']} ({b['deviation_pct']:+.0f}%). " + ("Partial routing-table loss?" if b["current"] < b["median"]
                                                                                           else "Possible route leak?"),
                             evidence={"peer": x["peer"], **b}, event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_route_leak(ch, now, p):
    out = []
    groups: dict = {}
    for e in await _bgp_events(ch, now, p["window_minutes"], set(p["kinds"])):
        groups.setdefault((e["firewall_id"], e["peer"], e["kind"]), []).append(e)
    for (fid, peer, kind), evs in groups.items():
        sample = ", ".join(sorted({e["prefix"] for e in evs if e["prefix"]})[:8])
        out.append(Detection(group_key=f"{fid}:{peer}:{kind}", count=len(evs), first_seen=evs[0]["t"], last_seen=evs[-1]["t"], firewall_ids=[fid],
                             dst_ip=peer or None, severity="high" if kind in ("leak_suspect", "more_specific") else "medium",
                             explanation=f"BGP {kind.replace('_', ' ')} from neighbor {peer} on {evs[0]['firewall_name']}: {evs[-1]['detail']}"
                                         + (f" Prefixes: {sample}." if sample else ""),
                             evidence={"kind": kind, "peer": peer, "prefixes": sorted({e["prefix"] for e in evs if e["prefix"]})[:50]},
                             event_filter={"category": ["system"], "q": f'"{peer}"'} if peer else {}))
    return out


async def rule_bgp_critical_prefix(ch, now, p):
    from ..bgp import _critical_nets
    from ..bgp_analysis import matches_watchlist
    from ..db.pg import session_factory
    async with session_factory()() as s:
        _, nets = await _critical_nets(s, p["watchlist"])
    if not nets:
        return []
    out = []
    for e in await _bgp_events(ch, now, p["window_minutes"], {"route_withdraw", "path_change", "unreachable"}):
        if not e["prefix"] or not matches_watchlist(e["prefix"], nets):
            continue
        out.append(Detection(group_key=f"{e['firewall_id']}:{e['prefix']}:{e['kind']}", count=1, first_seen=e["t"], last_seen=e["t"],
                             firewall_ids=[e["firewall_id"]], dst_ip=e["peer"] or None,
                             explanation=f"Critical prefix {e['prefix']} on {e['firewall_name']}: {e['kind'].replace('_', ' ')}"
                                         + (f" ({e['detail']})" if e["detail"] else "") + (f" via neighbor {e['peer']}" if e["peer"] else "") + ".",
                             evidence={"prefix": e["prefix"], "kind": e["kind"], "peer": e["peer"], "detail": e["detail"]}))
    return out


async def rule_bgp_peer_down(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"], correlate=True))["peers"]:
        for d in x["down_periods"]:
            if d["duration_s"] < int(p["min_down_minutes"]) * 60:
                continue
            out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=1, first_seen=_dt(d["start"]), last_seen=_dt(d["end"]),
                                 firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                                 explanation=f"BGP neighbor {x['peer']}" + (f" (AS {x['remote_as']})" if x["remote_as"] else "") +
                                             f" on {x['firewall_name']} {'is down' if d['ongoing'] else 'was down'} for {d['duration_s'] / 60:.0f} min"
                                             + (f": {x['last_reason']}" if x["last_reason"] else "") + "."
                                             + (f" Likely cause: {d['verdict']}." if d.get("verdict") else ""),
                                 evidence={**d, "peer": x["peer"], "remote_as": x["remote_as"], "reason": x["last_reason"], "tunnel": x["interface"]},
                                 event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_peer_flap(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"]))["peers"]:
        if x["flaps"] < int(p["min_flaps"]):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=x["flaps"], first_seen=now - timedelta(minutes=int(p["window_minutes"])),
                             last_seen=_dt(x["last_event"]) if x["last_event"] else now, firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                             explanation=f"BGP neighbor {x['peer']} on {x['firewall_name']} went down {x['flaps']} times in "
                                         f"{p['window_minutes']} min" + (f" (last: {x['last_reason']})" if x["last_reason"] else "") + ".",
                             evidence={"flaps": x["flaps"], "notifications": x["notifications"], "peer": x["peer"]},
                             event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out


async def rule_bgp_route_withdrawals(ch, now, p):
    out = []
    for x in (await _bgp_report(ch, now, p["window_minutes"]))["peers"]:
        if x["routes_withdrawn"] < int(p["min_withdrawals"]):
            continue
        out.append(Detection(group_key=f"{x['firewall_id']}:{x['peer']}", count=x["routes_withdrawn"],
                             first_seen=now - timedelta(minutes=int(p["window_minutes"])), last_seen=_dt(x["last_event"]) if x["last_event"] else now,
                             firewall_ids=[x["firewall_id"]], dst_ip=x["peer"],
                             explanation=f"{x['routes_withdrawn']} BGP route withdrawals for neighbor {x['peer']} on {x['firewall_name']} "
                                         f"in {p['window_minutes']} min ({x['routes_added']} announcements).",
                             evidence={"withdrawn": x["routes_withdrawn"], "added": x["routes_added"], "peer": x["peer"]},
                             event_filter={"category": ["system"], "q": f'"{x["peer"]}"'}))
    return out



RULES = {
    "risky_config_change": rule_risky_config_change, "isp_outage": rule_isp_outage, "fw_resource_high": rule_fw_resource_high,
    "fw_reboot": rule_fw_reboot, "log_feed_gap": rule_log_feed_gap, "vpn_tunnel_down": rule_vpn_tunnel_down,
    "icmp_down": rule_icmp_down, "iac_drift": rule_iac_drift,
    "bgp_peer_down": rule_bgp_peer_down, "bgp_peer_flap": rule_bgp_peer_flap, "bgp_route_withdrawals": rule_bgp_route_withdrawals,
    "bgp_prefix_anomaly": rule_bgp_prefix_anomaly, "bgp_route_leak": rule_bgp_route_leak, "bgp_critical_prefix": rule_bgp_critical_prefix,
}
_MODULES = (_switches, _tacacs, _wan, _wireless, _nms, _anomaly, _configs, _traffic)
for _m in _MODULES:
    RULES.update(_m.RULES)
    DEFAULT_RULES += _m.DEFAULT_RULES
AUTO_RESOLVE = set().union(*(_m.AUTO_RESOLVE for _m in _MODULES))


async def _maintenance(s: AsyncSession, now):
    """Admission: NMS maintenance windows hold back new alerts of the devices they cover."""
    from ..nms.maintenance import matcher
    return await matcher(s, now)


async def _resolve(s: AsyncSession, rule_key: str, active: set, now) -> list:
    """Stateful switch / TACACS+ / WAN / wireless conditions resolve themselves and notify recovery."""
    from ..notify import alert_resolved
    done = await _switches.resolve_cleared(s, rule_key, active, now)
    for a in done:
        await alert_resolved(s, a)
    return done


async def after_run(s: AsyncSession, ch, touched: list, now, result: dict) -> None:
    """Notify on new NMS alerts."""
    from ..notify import alert_created
    try:
        for a, created in touched:
            if created:
                await alert_created(s, a)
        await s.commit()
    except Exception:
        await s.rollback()
        log.exception("notification failed")


engine.register("nms", rules=RULES, defaults=DEFAULT_RULES, auto_resolve=AUTO_RESOLVE, resolver=_resolve,
                admission=_maintenance, after_run=after_run)
