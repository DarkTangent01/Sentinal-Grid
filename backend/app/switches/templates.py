"""Monitoring templates: reusable profiles per kind of device (polling intervals per metric group, alert thresholds,
interface rules). Built-in templates are seeded once and can be edited; administrators can add their own.

Resolution order for every setting is device override → template → default: the poller reads
Switch.template_config (a copy of the template made when it is applied or the template changes), so a poll never
needs another query. Interface utilisation thresholds resolve interface → device → template → global rule parameters.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import MonitoringTemplate, Switch

UTIL_DEFAULTS = {"util_warn_pct": 70, "util_high_pct": 85, "util_crit_pct": 95}
_OFF_L2 = {"poe": 0, "stp": 0, "mac_table": 0, "vlans": 0, "lacp": 0}
_SERVER = {**_OFF_L2, "stack": 0, "routing": 0, "neighbors": 0, "storage": 300}
_MINIMAL = {**_SERVER, "storage": 0, "cpu_memory": 0, "environment": 0, "inventory": 3600, "vendor_health": 0}
# interface types that never carry user traffic worth alerting on (IANAifType): 24 softwareLoopback
_NO_LOOPBACK = {"exclude_types": [24]}

BUILTIN: list[dict] = [
    {"key": "generic", "name": "Generic SNMP Device", "device_type": "other", "group_intervals": {**_OFF_L2, "stack": 0},
     "description": "Availability, interfaces and traffic, CPU / memory / storage where the device supports HOST-RESOURCES or ENTITY MIBs."},
    {"key": "switch", "name": "Generic Network Switch", "device_type": "switch", "group_intervals": {},
     "description": "Everything a switch exposes: interfaces, LAGs, VLANs, MAC table, spanning tree, PoE, neighbours, hardware."},
    {"key": "router", "name": "Router", "device_type": "router", "group_intervals": {"poe": 0, "stp": 0, "mac_table": 0, "routing": 300},
     "description": "Interfaces and traffic, routing neighbours (OSPF / BGP), hardware health."},
    {"key": "firewall", "name": "Firewall", "device_type": "firewall", "group_intervals": {"poe": 0, "stp": 0, "mac_table": 0},
     "description": "Interfaces, sessions / HA / VPN health from the vendor MIB, CPU and memory."},
    {"key": "wlc", "name": "Wireless Controller", "device_type": "wlc", "group_intervals": {"poe": 0, "stp": 0, "mac_table": 0},
     "description": "Controller interfaces and health; access points, radios and clients through the wireless groups."},
    {"key": "ap", "name": "Access Point", "device_type": "ap", "poll_interval_seconds": 120, "group_intervals": {**_OFF_L2, "routing": 0, "stack": 0},
     "description": "Availability, uplink interface traffic and errors."},
    {"key": "linux", "name": "Linux Server", "device_type": "linux", "group_intervals": _SERVER, "interface_rules": _NO_LOOPBACK,
     "thresholds": {"cpu_pct": 90, "mem_pct": 90, "storage_pct": 90},
     "description": "net-snmp: CPU, memory, file systems (HOST-RESOURCES / UCD-SNMP), network interfaces."},
    {"key": "windows", "name": "Windows Server", "device_type": "windows", "group_intervals": _SERVER, "interface_rules": _NO_LOOPBACK,
     "thresholds": {"cpu_pct": 90, "mem_pct": 90, "storage_pct": 90},
     "description": "Windows SNMP service: CPU, memory and volumes (HOST-RESOURCES), network adapters."},
    {"key": "ups", "name": "UPS", "device_type": "ups", "poll_interval_seconds": 60, "group_intervals": {**_MINIMAL, "ups": 60},
     "description": "UPS-MIB: battery status and charge, runtime remaining, load, on-battery state, input / output voltage."},
    {"key": "printer", "name": "Printer", "device_type": "printer", "poll_interval_seconds": 300, "group_intervals": {**_MINIMAL, "printer": 600},
     "description": "Printer-MIB: status, error conditions, supply levels, page count."},
]
BY_TYPE = {"switch": "switch", "l3switch": "switch", "router": "router", "firewall": "firewall", "wlc": "wlc", "ap": "ap", "linux": "linux",
           "windows": "windows", "server": "linux", "hypervisor": "linux", "storage": "generic", "load_balancer": "router", "ups": "ups",
           "printer": "printer", "appliance": "generic", "iot": "generic", "other": "generic"}


async def ensure_builtin(s: AsyncSession) -> None:
    """Create the built-in templates that do not exist yet (an edited built-in is never overwritten)."""
    have = set((await s.execute(select(MonitoringTemplate.key).where(MonitoringTemplate.key.isnot(None)))).scalars())
    names = set((await s.execute(select(MonitoringTemplate.name))).scalars())
    added = False
    for t in BUILTIN:
        if t["key"] in have or t["name"] in names:
            continue
        s.add(MonitoringTemplate(key=t["key"], name=t["name"], device_type=t["device_type"], description=t["description"],
                                 poll_interval_seconds=t.get("poll_interval_seconds", 60), group_intervals=dict(t.get("group_intervals") or {}),
                                 thresholds={**UTIL_DEFAULTS, **(t.get("thresholds") or {})}, interface_rules=dict(t.get("interface_rules") or {}),
                                 builtin=True, created_by="system"))
        added = True
    if added:
        await s.commit()


def snapshot(t: MonitoringTemplate | None) -> dict:
    if t is None:
        return {}
    return {"id": t.id, "name": t.name, "poll_interval_seconds": t.poll_interval_seconds, "group_intervals": dict(t.group_intervals or {}),
            "thresholds": dict(t.thresholds or {}), "interface_rules": dict(t.interface_rules or {}),
            "applied_at": datetime.now(timezone.utc).isoformat()}


async def template_for_type(s: AsyncSession, device_type: str) -> MonitoringTemplate | None:
    await ensure_builtin(s)
    key = BY_TYPE.get(device_type or "other", "generic")
    return (await s.execute(select(MonitoringTemplate).where(MonitoringTemplate.key == key))).scalars().first()


async def apply(s: AsyncSession, sw: Switch, t: MonitoringTemplate | None) -> None:
    sw.template_id = t.id if t else None
    sw.template_config = snapshot(t)


async def propagate(s: AsyncSession, t: MonitoringTemplate) -> int:
    """A template changed: refresh the copy on every device that uses it."""
    n = 0
    for sw in (await s.execute(select(Switch).where(Switch.template_id == t.id))).scalars():
        sw.template_config = snapshot(t)
        n += 1
    return n


def interface_threshold(iface_thresholds: dict | None, sw: Switch, rule_params: dict, key: str):
    """Interface → device → template → rule parameter → built-in default."""
    for src in (iface_thresholds or {}, sw.thresholds or {}, (sw.template_config or {}).get("thresholds") or {}, rule_params or {}, UTIL_DEFAULTS):
        if src.get(key) is not None:
            return src[key]
    return None


def interface_excluded(sw: Switch, if_type: int | None, name: str) -> bool:
    """Template interface rules: excluded types / names are stored but not alerted on."""
    rules = (sw.template_config or {}).get("interface_rules") or {}
    if if_type is not None and if_type in (rules.get("exclude_types") or []):
        return True
    rx = rules.get("exclude_regex")
    if rx:
        try:
            return bool(re.search(rx, name or ""))
        except re.error:
            return False
    return False
