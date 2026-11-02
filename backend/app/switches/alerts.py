"""Switch alert rules for the SIEM alert engine (same Detection / dedup / notification / incident pipeline as the
firewall rules).

* De-duplication: one alert per condition (group key = switch + component [+ start time for outages]); later polls
  update the open alert instead of creating new ones, so nothing is re-notified every polling cycle.
* Recovery: rules marked AUTO_RESOLVE resolve their open alerts when the condition clears and send an
  "alert.resolved" notification (routing rules opt in to that event type).
* Correlation: alerts carry the switch's site and the firewalls registered at that site, so a switch outage lands in
  the same incident as the site's FortiGate ISP / VPN / reachability alerts.
* No false spikes: rate-based rules ignore samples flagged GAP, RESET or UNCERTAIN_UTIL, and every rule requires the
  switch to have been polled successfully recently.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.models import Firewall, Switch, SwitchEvent, SwitchInterface
from ..db.pg import session_factory
from .rates import GAP, RESET, UNCERTAIN_UTIL

M = lambda tactic="", *t: ({"tactic": tactic, "techniques": list(t)} if tactic else {})  # noqa: E731

TROUBLE = {
    "switch_unreachable": ["Ping the management address from the SIEM and from the site firewall", "Check the uplink / upstream switch and power at the site",
                           "Check the switch's SNMP ACL and that UDP 161 is permitted end to end"],
    "switch_snmp_auth": ["Compare the SNMPv3 user, auth / priv protocols and passphrases with the switch (show snmp user)",
                         "Check whether the switch's engine ID changed (re-image, replacement): keys are localised to it"],
    "switch_stale_metrics": ["Open the switch's Monitoring Health tab: failed OIDs and timeouts per group", "Check the worker container is running",
                             "Raise the SNMP timeout for slow or busy switches"],
    "switch_cpu_high": ["show processes cpu sorted (Cisco) / show cpu-utilization (ICX)", "Look for broadcast storms, STP changes or a loop at the same time"],
    "switch_memory_high": ["show memory statistics / show memory (ICX)", "Check for a known memory leak in the running firmware release notes"],
    "switch_vendor_condition": ["Open the device's Vendor health tab for the component and its state",
                                "FortiGate: get system ha status / diagnose vpn tunnel list / diagnose sys sdwan health-check",
                                "Junos: show chassis alarms / show chassis environment"],
    "switch_storage_high": ["Find the largest files / logs on the volume (du, show flash:)", "Remove old images, core dumps and rotated logs",
                            "Check whether log rotation stopped"],
    "switch_temperature_high": ["Check fans and airflow in the rack, blanking panels, room temperature", "Compare with the other switches in the same rack"],
    "switch_psu_failure": ["Check the power cord / PDU feed of the failed supply", "show environment power (Cisco) / show chassis (ICX)"],
    "switch_fan_failure": ["Replace or reseat the fan module", "Watch temperatures until it is fixed"],
    "switch_poe_budget": ["List PoE consumers (show power inline / show inline power)", "Add a power supply or move high-draw devices to another switch"],
    "switch_port_down": ["Check the far end of the link and the cable / optic", "show interface <port> for err-disabled, CRC or flap history"],
    "switch_port_up_unexpected": ["Confirm who connected a device to a port documented as unused", "Check the MAC address table for that port"],
    "switch_if_utilization": ["Identify top talkers on the link (NetFlow / firewall traffic logs for the subnet)", "Consider adding a member to the LAG"],
    "switch_if_errors": ["Replace the cable / optic, clean fibre ends", "Check duplex mismatch and the far-end interface counters"],
    "switch_if_discards": ["Check output queue drops and QoS policy on the port", "Look for micro-bursts toward slower links"],
    "switch_if_flapping": ["Check the cable, optic and the far-end device", "Consider link-flap err-disable / dampening on the port"],
    "switch_stp_topology": ["Find the port causing topology changes (show spanning-tree detail | inc from)", "Enable portfast / edge on access ports"],
    "switch_stp_root_change": ["Confirm the intended root bridge priority", "Enable root guard on ports toward access switches"],
    "switch_lacp_member": ["show etherchannel summary / show lag", "Check the member link and the partner's LACP configuration"],
    "switch_stack_member": ["show switch / show stack", "Check stack cables and the member's power"],
    "switch_mac_move": ["Check for a loop (STP topology changes at the same time) or a device moving between ports",
                        "If the MAC belongs to a gateway or server, check for spoofing (port security / DHCP snooping)"],
    "switch_restart": ["show version (last reload reason)", "Check power at the site and crash files"],
    "switch_firmware_change": ["Confirm the change was approved", "Compare running and startup software versions across the stack"],
    "switch_routing_neighbor": ["show ip ospf neighbor / show ip bgp summary", "Check the routed link and authentication"],
    "switch_topology_link_lost": ["show lldp neighbors / show cdp neighbors on both ends", "Check the cable / optic and whether LLDP was disabled on the port",
                                  "Open Switch Monitoring → Topology and run a path check between the two devices"],
}

DEFAULT_RULES = [
    {"key": "switch_unreachable", "name": "Switch unreachable (SNMP)", "severity": "high", "mitre": {},
     "description": "A monitored switch stopped answering SNMP for its consecutive-failure threshold.", "params": {"min_down_minutes": 2}},
    {"key": "switch_snmp_auth", "name": "Switch SNMP authentication failing", "severity": "high", "mitre": M("TA0005", "T1562"),
     "description": "The switch rejects the monitoring credentials (wrong SNMPv3 user / keys, or the engine ID changed).", "params": {}},
    {"key": "switch_stale_metrics", "name": "Switch metrics stale or polling failing", "severity": "medium", "mitre": {},
     "description": "A switch's metrics are older than 3 poll intervals, or a metric group keeps failing while the switch answers.",
     "params": {"failing_minutes": 15}},
    {"key": "switch_cpu_high", "name": "Switch CPU high", "severity": "medium", "mitre": {},
     "description": "Switch CPU utilisation over the threshold for several consecutive polls.", "params": {"cpu_pct": 90, "min_samples": 3, "window_minutes": 10}},
    {"key": "switch_memory_high", "name": "Switch memory high", "severity": "medium", "mitre": {},
     "description": "Switch memory utilisation over the threshold for several consecutive polls.", "params": {"mem_pct": 90, "min_samples": 3, "window_minutes": 10}},
    {"key": "switch_vendor_condition", "name": "Vendor health condition (HA, VPN, SD-WAN, chassis alarm)", "severity": "high", "mitre": {},
     "description": "A vendor adapter reports an abnormal state: FortiGate HA not synchronised, IPsec tunnel or SD-WAN member down; Junos red / yellow "
                    "chassis alarm or a component down. Severity comes from the adapter.", "params": {}},
    {"key": "switch_storage_high", "name": "Device storage almost full", "severity": "medium", "mitre": {},
     "description": "A disk, flash or file system (HOST-RESOURCES-MIB hrStorage) stayed over the threshold for several consecutive polls.",
     "params": {"storage_pct": 90, "min_samples": 2, "window_minutes": 20}},
    {"key": "switch_temperature_high", "name": "Switch temperature high", "severity": "high", "mitre": {},
     "description": "A temperature sensor is over the threshold, or the switch reports a warning / critical state.", "params": {"celsius": 65}},
    {"key": "switch_psu_failure", "name": "Switch power supply failure", "severity": "high", "mitre": {},
     "description": "A present power supply reports a failure, warning or shutdown state.", "params": {}},
    {"key": "switch_fan_failure", "name": "Switch fan failure", "severity": "high", "mitre": {},
     "description": "A fan reports a failure, warning or shutdown state.", "params": {}},
    {"key": "switch_poe_budget", "name": "Switch PoE budget nearly exhausted", "severity": "medium", "mitre": {},
     "description": "PoE power in use is close to the switch's (or stack member's) budget: new devices may be denied power.", "params": {"pct": 90}},
    {"key": "switch_port_down", "name": "Switch uplink / watched port down", "severity": "medium", "mitre": {},
     "description": "An uplink (trunk, LAG member, port-channel, or a description matching the watch pattern) went down and stayed down.",
     "params": {"min_down_minutes": 2, "watch_regex": "(?i)uplink|core|server|ap-|wan"}},
    {"key": "switch_port_up_unexpected", "name": "Unexpected port up", "severity": "low", "mitre": M("TA0001", "T1200"),
     "description": "A port documented as unused (description matching the pattern) came up.", "params": {"window_minutes": 30, "unused_regex": "(?i)unused|spare|disabled|reserved"}},
    {"key": "switch_if_utilization", "name": "Switch interface utilisation high", "severity": "medium", "mitre": {},
     "description": "Inbound or outbound utilisation over the threshold for consecutive valid samples (samples with gaps, counter resets or "
                    "uncertain speed are ignored).", "params": {"util_pct": 90, "min_samples": 3, "window_minutes": 15}},
    {"key": "switch_if_errors", "name": "Switch interface errors (CRC / input / output)", "severity": "medium", "mitre": {},
     "description": "CRC / FCS, input or output errors on an interface over the threshold within the window.",
     "params": {"min_errors": 100, "window_minutes": 15}},
    {"key": "switch_if_discards", "name": "Switch interface discards", "severity": "low", "mitre": {},
     "description": "Input or output discards on an interface over the threshold within the window.", "params": {"min_discards": 1000, "window_minutes": 15}},
    {"key": "switch_if_flapping", "name": "Switch interface flapping", "severity": "medium", "mitre": {},
     "description": "An interface changed state repeatedly within the window.", "params": {"min_changes": 4, "window_minutes": 30}},
    {"key": "switch_stp_topology", "name": "Frequent spanning-tree topology changes", "severity": "medium", "mitre": {},
     "description": "Many STP topology changes within the window (flapping edge ports, loops).", "params": {"min_changes": 10, "window_minutes": 60}},
    {"key": "switch_stp_root_change", "name": "Spanning-tree root bridge changed", "severity": "high", "mitre": M("TA0040", "T1498"),
     "description": "The STP root bridge changed: an intended topology change, a failure of the root, or a rogue switch with a better priority.",
     "params": {"window_minutes": 30, "expected_roots": []}},
    {"key": "switch_lacp_member", "name": "Port-channel degraded (LACP member)", "severity": "medium", "mitre": {},
     "description": "A LAG member left the bundle or was removed while the port-channel stays configured.", "params": {"window_minutes": 60}},
    {"key": "switch_stack_member", "name": "Switch stack member failure", "severity": "high", "mitre": {},
     "description": "A stack member is missing, not ready, or the stack ring lost redundancy.", "params": {}},
    {"key": "switch_mac_move", "name": "MAC address movement anomaly", "severity": "medium", "mitre": M("TA0006", "T1557"),
     "description": "The same MAC moved between ports repeatedly, many MACs moved at once, or a burst of new MACs was learned. Possible causes: "
                    "a loop, a device roaming between ports, a misconfigured LAG, or spoofing; the evidence lists the ports.",
     "params": {"window_minutes": 30, "min_moves_per_mac": 3, "min_moves_per_switch": 50, "ignore_port_regex": ""}},
    {"key": "switch_restart", "name": "Switch restarted", "severity": "high", "mitre": {},
     "description": "sysUpTime went backwards between polls: the switch (or its SNMP agent) restarted.", "params": {"window_minutes": 60}},
    {"key": "switch_firmware_change", "name": "Switch firmware changed", "severity": "medium", "mitre": M("TA0003", "T1601"),
     "description": "The switch's software version or identification changed between polls.", "params": {"window_minutes": 120}},
    {"key": "switch_topology_link_lost", "name": "Switch topology link lost (LLDP / CDP)", "severity": "medium", "mitre": {},
     "description": "An LLDP / CDP neighbor that is a monitored switch, a firewall, a router or a bridge is no longer seen on a port: the link "
                    "between two network devices went away (cable, optic, far-end failure) or LLDP was disabled.", "params": {"window_hours": 24}},
    {"key": "switch_routing_neighbor", "name": "Switch routing neighbor down (OSPF / BGP)", "severity": "high", "mitre": {},
     "description": "An OSPF or BGP neighbor of a layer-3 switch left the full / established state.", "params": {"window_minutes": 60}},
]
AUTO_RESOLVE = {"switch_vendor_condition", "switch_unreachable", "switch_snmp_auth", "switch_stale_metrics", "switch_cpu_high", "switch_memory_high", "switch_storage_high",
                "switch_temperature_high",
                "switch_psu_failure", "switch_fan_failure", "switch_poe_budget", "switch_port_down", "switch_if_utilization", "switch_lacp_member",
                "switch_stack_member", "switch_routing_neighbor", "switch_topology_link_lost"}


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


async def _context():
    async with session_factory()() as s:
        sws = (await s.execute(select(Switch).where(Switch.monitoring == "active"))).scalars().all()
        fws = (await s.execute(select(Firewall.id, Firewall.site).where(Firewall.is_demo.is_(False)))).all()
    by_site: dict[str, list[int]] = {}
    for f in fws:
        if f.site:
            by_site.setdefault(f.site.strip().lower(), []).append(f.id)
    return sws, by_site


def _det(sw: Switch, by_site, key: str, rule: str, explanation: str, *, first, last, count=1, component="", metric="", value=None,
         threshold=None, severity=None, last_healthy=None, extra: dict | None = None):
    from ..alerts.engine import Detection
    ev = {"switch": sw.name, "switch_id": sw.id, "management_ip": sw.address, "site": sw.site, "vendor": sw.vendor, "model": sw.model,
          "component": component, "metric": metric, "observed": value, "threshold": threshold, "detected_at": last.isoformat(),
          "last_healthy": last_healthy, "troubleshooting": TROUBLE.get(rule, []), "link": f"/switches/{sw.id}", **(extra or {})}
    return Detection(group_key=key, count=count, first_seen=first, last_seen=last, explanation=explanation, dst_ip=sw.address,
                     firewall_ids=by_site.get((sw.site or "").strip().lower(), []), sites=[sw.site] if sw.site else [], evidence=ev,
                     event_filter={}, severity=severity)


def _fresh(sw: Switch, now) -> bool:
    last = _aware(sw.last_success_at)
    return bool(last and (now - last).total_seconds() <= 3 * max(60, sw.poll_interval_seconds or 60) + 120)


def _thr(sw: Switch, p: dict, k: str):
    return (sw.thresholds or {}).get(k, p.get(k))


async def _events(kinds: list[str], since: datetime) -> list[SwitchEvent]:
    async with session_factory()() as s:
        return (await s.execute(select(SwitchEvent).where(SwitchEvent.kind.in_(kinds), SwitchEvent.at >= since).order_by(SwitchEvent.at))).scalars().all()


def down_root(sw: Switch, by_id: dict) -> Switch | None:
    """Topmost unreachable device on sw's upstream chain (parent_id), or None. A device behind a down parent is not
    alerted on its own: the parent's alert is the root cause and lists it (LibreNMS / Zabbix dependencies)."""
    root, seen, cur = None, {sw.id}, by_id.get(sw.parent_id)
    while cur is not None and cur.id not in seen:
        seen.add(cur.id)
        if cur.state == "down":
            root = cur
        cur = by_id.get(cur.parent_id)
    return root


async def rule_switch_unreachable(ch, now, p):
    sws, bs = await _context()
    by_id = {x.id: x for x in sws}
    dependents: dict[int, list[str]] = {}
    down = []
    for sw in sws:
        if sw.state != "down":
            continue
        root = down_root(sw, by_id)
        if root is not None:
            dependents.setdefault(root.id, []).append(sw.name)
            continue
        down.append(sw)
    out = []
    for sw in down:
        since = _aware(sw.state_since) or now
        mins = (now - since).total_seconds() / 60
        if mins < float(p.get("min_down_minutes", 2)):
            continue
        deps = sorted(dependents.get(sw.id, []))
        out.append(_det(sw, bs, f"{sw.id}:{since:%Y%m%d%H%M%S}", "switch_unreachable",
                        f"{sw.name} ({sw.address}) has not answered SNMP for {mins:.0f} min ({sw.fail_streak} failed polls): {sw.last_error}"
                        + (f" — {len(deps)} downstream device(s) unreachable behind it are not alerted separately" if deps else ""),
                        first=since, last=now, count=sw.fail_streak, component="SNMP agent", metric="switch_up", value=0,
                        last_healthy=sw.last_success_at.isoformat() if sw.last_success_at else None,
                        extra={"dependent_devices": deps} if deps else None))
    return out


async def rule_switch_snmp_auth(ch, now, p):
    sws, bs = await _context()
    return [_det(sw, bs, f"{sw.id}:{(_aware(sw.state_since) or now):%Y%m%d%H%M%S}", "switch_snmp_auth",
                 f"{sw.name} ({sw.address}) rejects the SNMP credentials: {sw.last_error}", first=_aware(sw.state_since) or now, last=now,
                 component="SNMP credentials", metric="switch_up", value=0) for sw in sws if sw.state == "auth_failed"]


async def rule_switch_stale_metrics(ch, now, p):
    from .poller import intervals_of
    from .registry import status_of
    sws, bs = await _context()
    out = []
    for sw in sws:
        if sw.state != "up":
            continue
        last = _aware(sw.last_success_at)
        iv = max(60, sw.poll_interval_seconds or 60)
        if last and (now - last).total_seconds() > 3 * iv + 60:
            out.append(_det(sw, bs, f"{sw.id}:stale", "switch_stale_metrics", f"{sw.name}: no successful poll for {(now - last).total_seconds() / 60:.0f} min "
                            f"(interval {iv}s). Check the worker.", first=last, last=now, component="poller", metric="last_success_age_seconds",
                            value=round((now - last).total_seconds()), threshold=3 * iv))
            continue
        ivs = intervals_of(sw)
        failing = []
        for k, rec in (sw.capabilities or {}).items():
            if status_of(rec, now, ivs.get(rec.get("group", ""), 60)) == "failed":
                err = rec.get("last_error") or {}
                okt = _aware(datetime.fromisoformat(rec["last_success"])) if rec.get("last_success") else None
                if okt is None or (now - okt).total_seconds() >= 60 * float(p.get("failing_minutes", 15)):
                    failing.append((k, err.get("message", "")))
        if failing:
            out.append(_det(sw, bs, f"{sw.id}:failing", "switch_stale_metrics",
                            f"{sw.name}: {len(failing)} metric(s) failing to collect: " + "; ".join(f"{k} ({m})" for k, m in failing[:5]),
                            first=now, last=now, count=len(failing), component="metric collection", metric="failed_metrics", value=len(failing),
                            extra={"failed": [k for k, _ in failing]}))
    return out


async def _sustained(ch, now, p, metric: str, key_pct: str, label: str, rule: str):
    sws, bs = await _context()
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 10)))
    rows = await ch.aquery("SELECT switch_id, component, ts, value FROM switch_metrics WHERE metric = {m:String} AND ts >= {t0:DateTime64(3)} "
                           "ORDER BY switch_id, component, ts", {"m": metric, "t0": t0})
    series: dict = {}
    for r in rows:
        series.setdefault((int(r["switch_id"]), r["component"]), []).append(float(r["value"]))
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        thr = float(_thr(sw, p, key_pct))
        n = int(p.get("min_samples", 3))
        for (sid, comp), vals in series.items():
            if sid != sw.id or len(vals) < n or not all(v >= thr for v in vals[-n:]):
                continue
            out.append(_det(sw, bs, f"{sw.id}:{comp}", rule, f"{sw.name}{' ' + comp if comp else ''}: {label} {vals[-1]:.0f}% "
                            f"(≥ {thr:.0f}% for the last {n} polls)", first=t0, last=now, count=n, component=comp or label, metric=metric,
                            value=vals[-1], threshold=thr))
    return out


async def rule_switch_cpu_high(ch, now, p):
    return await _sustained(ch, now, p, "switch_cpu_utilization_percent", "cpu_pct", "CPU", "switch_cpu_high")


async def rule_switch_vendor_condition(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        for a in ((sw.health or {}).get("vendor") or {}).get("alarms") or []:
            out.append(_det(sw, bs, f"{sw.id}:{a['key']}", "switch_vendor_condition", f"{sw.name} — {a['component']}: {a['detail']}", first=now, last=now,
                            component=a["component"], metric="vendor_health", severity=a.get("severity"), extra={"condition": a["key"]}))
    return out


async def rule_switch_storage_high(ch, now, p):
    return await _sustained(ch, now, p, "switch_storage_used_percent", "storage_pct", "storage used", "switch_storage_high")


async def rule_switch_memory_high(ch, now, p):
    return await _sustained(ch, now, p, "switch_memory_utilization_percent", "mem_pct", "memory", "switch_memory_high")


async def rule_switch_temperature_high(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        thr = float(_thr(sw, p, "celsius"))
        for t in ((sw.health or {}).get("environment") or {}).get("temperatures") or []:
            c = t.get("celsius")
            dev_thr = t.get("threshold")
            if c is None:
                continue
            hot = c >= thr or (dev_thr and c >= dev_thr) or t.get("state") in ("warning", "critical", "shutdown")
            if hot:
                out.append(_det(sw, bs, f"{sw.id}:{t['name']}", "switch_temperature_high", f"{sw.name} {t['name']}: {c} °C "
                                f"(threshold {dev_thr or thr} °C, state {t.get('state')})", first=now, last=now, component=t["name"],
                                metric="switch_temperature_celsius", value=c, threshold=dev_thr or thr,
                                severity="critical" if t.get("state") in ("critical", "shutdown") else None))
    return out


async def _component_failure(now, kind: str, rule: str, label: str):
    sws, bs = await _context()
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        for x in ((sw.health or {}).get("environment") or {}).get(kind) or []:
            if x.get("state") in ("failed", "critical", "warning", "shutdown"):
                out.append(_det(sw, bs, f"{sw.id}:{x['name']}", rule, f"{sw.name}: {label} {x['name']} is {x['state']}", first=now, last=now,
                                component=x["name"], metric=f"switch_{'psu' if kind == 'psus' else 'fan'}_status", value=x["state"], threshold="ok"))
    return out


async def rule_switch_psu_failure(ch, now, p):
    return await _component_failure(now, "psus", "switch_psu_failure", "power supply")


async def rule_switch_fan_failure(ch, now, p):
    return await _component_failure(now, "fans", "switch_fan_failure", "fan")


async def rule_switch_poe_budget(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        thr = float(_thr(sw, p, "pct"))
        for u in ((sw.health or {}).get("poe") or {}).get("units") or []:
            if u.get("budget_w") and u.get("used_w") is not None:
                pct = 100.0 * u["used_w"] / u["budget_w"]
                if pct >= thr:
                    out.append(_det(sw, bs, f"{sw.id}:poe:{u['unit']}", "switch_poe_budget", f"{sw.name} PoE unit {u['unit']}: {u['used_w']:.0f} W of "
                                    f"{u['budget_w']:.0f} W in use ({pct:.0f}%)", first=now, last=now, component=f"PoE unit {u['unit']}",
                                    metric="switch_poe_power_watts", value=round(pct, 1), threshold=thr))
    return out


async def rule_switch_port_down(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    rx = re.compile(p.get("watch_regex") or "$^")
    async with session_factory()() as s:
        rows = (await s.execute(select(SwitchInterface).where(SwitchInterface.present.is_(True), SwitchInterface.admin == "up",
                                                              SwitchInterface.oper.in_(["down", "lower_layer_down"])))).scalars().all()
    out = []
    for r in rows:
        sw = sw_by.get(r.switch_id)
        if sw is None or not _fresh(sw, now) or r.last_change_at is None:
            continue  # never seen up while monitored: not an unexpected down
        uplink = r.kind == "lag" or r.mode == "trunk" or r.lag_ifindex is not None
        if not (uplink or rx.search(r.alias or "")):
            continue
        since = _aware(r.last_change_at)
        if (now - since).total_seconds() < 60 * float(p.get("min_down_minutes", 2)):
            continue
        out.append(_det(sw, bs, f"{sw.id}:{r.ifindex}:{since:%Y%m%d%H%M%S}", "switch_port_down",
                        f"{sw.name} {r.name}{' (' + r.alias + ')' if r.alias else ''} is down since {since:%H:%M} UTC"
                        + (" (uplink / LAG member)" if uplink else ""), first=since, last=now, component=r.name, metric="switch_interface_up",
                        value=0, threshold=1, severity="high" if r.kind == "lag" else None, extra={"ifindex": r.ifindex, "uplink": uplink}))
    return out


async def rule_switch_port_up_unexpected(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    rx = re.compile(p.get("unused_regex") or "$^")
    out = []
    for e in await _events(["port_up"], now - timedelta(minutes=int(p.get("window_minutes", 30)))):
        sw = sw_by.get(e.switch_id)
        if sw and rx.search(e.component or ""):
            out.append(_det(sw, bs, f"{sw.id}:{e.data.get('ifindex')}:{e.id}", "switch_port_up_unexpected", f"{sw.name}: {e.component} came up",
                            first=_aware(e.at), last=_aware(e.at), component=e.component, metric="switch_interface_up", value=1, threshold=0))
    return out


async def _if_names(ids: set[int]) -> dict:
    async with session_factory()() as s:
        rows = (await s.execute(select(SwitchInterface.switch_id, SwitchInterface.ifindex, SwitchInterface.name, SwitchInterface.alias)
                                .where(SwitchInterface.switch_id.in_(ids or {0})))).all()
    return {(r.switch_id, r.ifindex): (r.name + (f" ({r.alias})" if r.alias else "")) for r in rows}


async def rule_switch_if_utilization(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws if _fresh(s, now)}
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    bad = GAP | RESET | UNCERTAIN_UTIL
    rows = await ch.aquery("SELECT switch_id, ifindex, ts, rx_util, tx_util, rx_bps, tx_bps FROM switch_if_samples WHERE ts >= {t0:DateTime64(3)} "
                           "AND bitAnd(flags, {bad:UInt8}) = 0 AND (rx_util IS NOT NULL OR tx_util IS NOT NULL) ORDER BY switch_id, ifindex, ts",
                           {"t0": t0, "bad": bad})
    series: dict = {}
    for r in rows:
        series.setdefault((int(r["switch_id"]), int(r["ifindex"])), []).append(r)
    names = await _if_names(set(sw_by))
    out = []
    n = int(p.get("min_samples", 3))
    for (sid, ifx), rs in series.items():
        sw = sw_by.get(sid)
        if sw is None or len(rs) < n:
            continue
        thr = float(_thr(sw, p, "util_pct"))
        last = rs[-n:]
        for d in ("rx", "tx"):
            if all((x[f"{d}_util"] or 0) >= thr for x in last):
                v = float(last[-1][f"{d}_util"])
                out.append(_det(sw, bs, f"{sid}:{ifx}:{d}", "switch_if_utilization", f"{sw.name} {names.get((sid, ifx), ifx)}: "
                                f"{'inbound' if d == 'rx' else 'outbound'} utilisation {v:.0f}% (≥ {thr:.0f}% for {n} samples, "
                                f"{float(last[-1][f'{d}_bps']) / 1e6:.0f} Mbit/s)", first=t0, last=now, count=n, component=names.get((sid, ifx), str(ifx)),
                                metric=f"switch_interface_{d}_utilization_percent", value=round(v, 1), threshold=thr, extra={"ifindex": ifx}))
    return out


async def _if_sum(ch, now, p, expr: str, key: str, rule: str, label: str):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws if _fresh(s, now)}
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    rows = await ch.aquery(f"SELECT switch_id, ifindex, sum({expr}) AS o_n, sum(ifNull(crc, 0)) AS o_crc, count() AS o_samples FROM switch_if_samples "
                           "WHERE ts >= {t0:DateTime64(3)} AND bitAnd(flags, {reset:UInt8}) = 0 GROUP BY switch_id, ifindex",
                           {"t0": t0, "reset": RESET})
    names = await _if_names(set(sw_by))
    out = []
    for r in rows:
        sw = sw_by.get(int(r["switch_id"]))
        if sw is None:
            continue
        thr = float(_thr(sw, p, key))
        n = int(r["o_n"] or 0)
        if n >= thr:
            ifx = int(r["ifindex"])
            out.append(_det(sw, bs, f"{sw.id}:{ifx}", rule, f"{sw.name} {names.get((sw.id, ifx), ifx)}: {n:,} {label} in "
                            f"{p.get('window_minutes', 15)} min" + (f" ({int(r['o_crc']):,} CRC / FCS)" if rule == "switch_if_errors" and r["o_crc"] else ""),
                            first=t0, last=now, count=n, component=names.get((sw.id, ifx), str(ifx)), metric=label.replace(" ", "_"), value=n,
                            threshold=thr, extra={"ifindex": ifx}))
    return out


async def rule_switch_if_errors(ch, now, p):
    return await _if_sum(ch, now, p, "ifNull(in_errors, 0) + ifNull(out_errors, 0) + ifNull(crc, 0)", "min_errors", "switch_if_errors", "errors")


async def rule_switch_if_discards(ch, now, p):
    return await _if_sum(ch, now, p, "ifNull(in_discards, 0) + ifNull(out_discards, 0)", "min_discards", "switch_if_discards", "discards")


async def rule_switch_if_flapping(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    by: dict = {}
    for e in await _events(["port_up", "port_down", "port_flap"], t0):
        by.setdefault((e.switch_id, e.data.get("ifindex"), e.component), []).append(e)
    out = []
    for (sid, ifx, comp), evs in by.items():
        sw = sw_by.get(sid)
        changes = sum(2 if e.kind == "port_flap" else 1 for e in evs)
        if sw and changes >= int(_thr(sw, p, "min_changes")):
            out.append(_det(sw, bs, f"{sid}:{ifx}", "switch_if_flapping", f"{sw.name} {comp}: {changes} state changes in {p.get('window_minutes', 30)} min",
                            first=_aware(evs[0].at), last=_aware(evs[-1].at), count=changes, component=comp, metric="interface_state_changes",
                            value=changes, threshold=_thr(sw, p, "min_changes"), extra={"ifindex": ifx, "events": [e.detail for e in evs[-10:]]}))
    return out


async def rule_switch_stp_topology(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 60)))
    by: dict = {}
    for e in await _events(["stp_topology_change"], t0):
        by.setdefault(e.switch_id, []).append(e)
    out = []
    for sid, evs in by.items():
        sw = sw_by.get(sid)
        n = sum(int(e.data.get("count") or 1) for e in evs)
        if sw and n >= int(_thr(sw, p, "min_changes")):
            out.append(_det(sw, bs, f"{sid}", "switch_stp_topology", f"{sw.name}: {n} STP topology changes in {p.get('window_minutes', 60)} min "
                            f"({', '.join(sorted({e.component for e in evs}))})", first=_aware(evs[0].at), last=_aware(evs[-1].at), count=n,
                            component="spanning tree", metric="switch_stp_topology_changes_total", value=n, threshold=_thr(sw, p, "min_changes")))
    return out


async def rule_switch_stp_root_change(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    expected = {str(x).lower() for x in p.get("expected_roots") or []}
    out = []
    for e in await _events(["stp_root_change"], now - timedelta(minutes=int(p.get("window_minutes", 30)))):
        sw = sw_by.get(e.switch_id)
        if sw and str(e.data.get("new", "")).lower() not in expected:
            out.append(_det(sw, bs, f"{sw.id}:{e.id}", "switch_stp_root_change", f"{sw.name}: {e.detail}", first=_aware(e.at), last=_aware(e.at),
                            component=e.component, metric="stp_root", value=e.data.get("new"), extra={"previous_root": e.data.get("old")}))
    return out


async def rule_switch_lacp_member(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        if not _fresh(sw, now):
            continue
        for lag in (((sw.health or {}).get("lacp") or {}).get("lags") or {}).values():
            down = [m["name"] for m in lag["members"] if m.get("in_bundle") is False]
            if down:
                out.append(_det(sw, bs, f"{sw.id}:{lag['ifindex']}", "switch_lacp_member", f"{sw.name} {lag['name']}: {len(down)} of "
                                f"{lag['total_members']} members not in the bundle ({', '.join(down)})", first=now, last=now, count=len(down),
                                component=lag["name"], metric="switch_lacp_member_up", value=lag["up_members"], threshold=lag["total_members"],
                                severity="high" if lag["up_members"] == 0 else None))
    sw_by = {s.id: s for s in sws}
    for e in await _events(["lacp_member_removed"], now - timedelta(minutes=int(p.get("window_minutes", 60)))):
        sw = sw_by.get(e.switch_id)
        if sw:
            out.append(_det(sw, bs, f"{sw.id}:removed:{e.id}", "switch_lacp_member", f"{sw.name}: {e.detail}", first=_aware(e.at), last=_aware(e.at),
                            component=e.component, metric="lag_membership"))
    return out


async def rule_switch_stack_member(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        st = (sw.health or {}).get("stack") or {}
        if not _fresh(sw, now) or not st:
            continue
        for m in st.get("members") or []:
            if not m.get("healthy"):
                out.append(_det(sw, bs, f"{sw.id}:unit{m['unit']}", "switch_stack_member", f"{sw.name}: stack member {m['unit']} is {m['state']}",
                                first=now, last=now, component=f"stack unit {m['unit']}", metric="switch_stack_member_state", value=m["state"], threshold="ready"))
        if st.get("ring_redundant") is False and len(st.get("members") or []) > 1:
            out.append(_det(sw, bs, f"{sw.id}:ring", "switch_stack_member", f"{sw.name}: stack ring is not redundant ({st.get('topology') or 'chain'})",
                            first=now, last=now, component="stack ring", metric="switch_stack_ring", value="chain", threshold="ring", severity="medium"))
    return out


async def rule_switch_mac_move(ch, now, p):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    ign = re.compile(p["ignore_port_regex"]) if p.get("ignore_port_regex") else None
    per_mac: dict = {}
    per_sw: dict = {}
    out = []
    for e in await _events(["mac_move", "mac_learning_burst"], t0):
        sw = sw_by.get(e.switch_id)
        if sw is None:
            continue
        if e.kind == "mac_learning_burst":
            out.append(_det(sw, bs, f"{sw.id}:burst:{e.id}", "switch_mac_move", f"{sw.name}: {e.detail}", first=_aware(e.at), last=_aware(e.at),
                            count=int(e.data.get("new") or 0), component="MAC table", metric="new_macs_per_poll", value=e.data.get("new")))
            continue
        if ign and (ign.search(e.data.get("from_port") or "") or ign.search(e.data.get("to_port") or "")):
            continue
        per_mac.setdefault((sw.id, e.data.get("mac"), e.data.get("vlan")), []).append(e)
        per_sw.setdefault(sw.id, []).append(e)
    for (sid, mac, vlan), evs in per_mac.items():
        sw = sw_by[sid]
        if len(evs) >= int(_thr(sw, p, "min_moves_per_mac")):
            ports = sorted({x for e in evs for x in (e.data.get("from_port"), e.data.get("to_port")) if x})
            out.append(_det(sw, bs, f"{sid}:{mac}:{vlan}", "switch_mac_move", f"{sw.name}: {mac} (VLAN {vlan}) moved {len(evs)} times between "
                            f"{', '.join(ports)} in {p.get('window_minutes', 30)} min", first=_aware(evs[0].at), last=_aware(evs[-1].at), count=len(evs),
                            component=f"VLAN {vlan}", metric="mac_moves", value=len(evs), threshold=_thr(sw, p, "min_moves_per_mac"),
                            extra={"mac": mac, "ports": ports, "moves": [e.detail for e in evs[-10:]]}))
    for sid, evs in per_sw.items():
        sw = sw_by[sid]
        if len(evs) >= int(_thr(sw, p, "min_moves_per_switch")):
            out.append(_det(sw, bs, f"{sid}:many", "switch_mac_move", f"{sw.name}: {len(evs)} MAC moves in {p.get('window_minutes', 30)} min "
                            f"({len({e.data.get('mac') for e in evs})} MACs)", first=_aware(evs[0].at), last=_aware(evs[-1].at), count=len(evs),
                            component="MAC table", metric="mac_moves", value=len(evs), threshold=_thr(sw, p, "min_moves_per_switch")))
    return out


async def _event_rule(now, p, kinds, rule):
    sws, bs = await _context()
    sw_by = {s.id: s for s in sws}
    return [_det(sw_by[e.switch_id], bs, f"{e.switch_id}:{e.id}", rule, f"{sw_by[e.switch_id].name}: {e.detail}", first=_aware(e.at), last=_aware(e.at),
                 component=e.component, metric=e.kind, extra=e.data) for e in await _events(kinds, now - timedelta(minutes=int(p.get("window_minutes", 60))))
            if e.switch_id in sw_by]


async def rule_switch_restart(ch, now, p):
    return await _event_rule(now, p, ["restart"], "switch_restart")


async def rule_switch_firmware_change(ch, now, p):
    return await _event_rule(now, p, ["firmware_change", "vendor_change"], "switch_firmware_change")


async def rule_switch_routing_neighbor(ch, now, p):
    sws, bs = await _context()
    out = []
    for sw in sws:
        r = (sw.health or {}).get("routing") or {}
        if not _fresh(sw, now):
            continue
        for kind, key, good in (("ospf", "neighbor", "full"), ("bgp", "peer", "established")):
            for x in r.get(kind) or []:
                if x["state"] != good and not (kind == "ospf" and x["state"] == "two-way"):
                    out.append(_det(sw, bs, f"{sw.id}:{kind}:{x[key]}", "switch_routing_neighbor", f"{sw.name}: {kind.upper()} neighbor {x[key]} is {x['state']}",
                                    first=now, last=now, component=f"{kind.upper()} {x[key]}", metric=f"switch_{kind}_neighbor_state", value=x["state"], threshold=good))
    return out


async def rule_switch_topology_link_lost(ch, now, p):
    from ..db.models import SwitchNeighbor
    from .topology import _short, node_type
    sws, bs = await _context()
    sw_by = {x.id: x for x in sws}
    names = {_short(n) for x in sws for n in (x.name, x.sys_name) if n} | {x.address for x in sws}
    async with session_factory()() as s:
        fws = (await s.execute(select(Firewall.name, Firewall.host).where(Firewall.is_demo.is_(False)))).all()
        rows = (await s.execute(select(SwitchNeighbor).where(SwitchNeighbor.present.is_(False),
                                                             SwitchNeighbor.last_seen >= now - timedelta(hours=int(p.get("window_hours", 24)))))).scalars().all()
        ifs = {(r.switch_id, r.ifindex): r for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.present.is_(True)))).scalars()}
    names |= {_short(f.name) for f in fws} | {f.host for f in fws}
    out = []
    for r in rows:
        sw = sw_by.get(r.switch_id)
        if sw is None or not _fresh(sw, now):
            continue
        infra = _short(r.remote_name) in names or r.remote_mgmt_ip in names or node_type(r.capabilities, r.remote_descr) in ("switch", "router", "firewall")
        if not infra:
            continue
        li = ifs.get((r.switch_id, r.local_ifindex))
        out.append(_det(sw, bs, f"{sw.id}:nbr:{r.local_ifindex}:{r.remote_key}", "switch_topology_link_lost",
                        f"{sw.name} {r.local_port}: neighbor {r.remote_name or r.remote_key} ({r.remote_port or '?'}) not seen since "
                        f"{_aware(r.last_seen):%H:%M} UTC" + (f"; local port is {li.oper}" if li else ""), first=_aware(r.last_seen), last=now,
                        component=r.local_port, metric="lldp_neighbor", value="absent", threshold="present",
                        severity="high" if li is not None and li.oper != "up" else None, last_healthy=_aware(r.last_seen).isoformat(),
                        extra={"remote": r.remote_name, "remote_port": r.remote_port, "remote_ip": r.remote_mgmt_ip, "protocol": r.protocol}))
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}


async def resolve_cleared(s, rule_key: str, active_keys: set[str], now: datetime) -> list:
    """Resolve open alerts of an auto-resolving switch rule whose condition no longer holds; returns them."""
    from ..db.models import Alert
    rows = (await s.execute(select(Alert).where(Alert.rule_key == rule_key, Alert.status.in_(["new", "investigating"])))).scalars().all()
    done = []
    for a in rows:
        if a.group_key in active_keys:
            continue
        a.status = "resolved"
        a.notes = ((a.notes or "") + f"\n[{now:%Y-%m-%d %H:%M} UTC] auto-resolved: condition cleared on the next poll").strip()
        done.append(a)
    return done
