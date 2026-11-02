"""Metric capability registry: every metric the switch module can collect, where it comes from, and how a device's
support for it is judged.

Sources are public MIB definitions (IETF standard MIBs; Cisco and Ruckus/Foundry enterprise MIBs). Standard MIB OIDs are
stable across vendors; enterprise OIDs are listed per vendor and are only ever requested from that vendor's devices.
Support is never assumed: each metric's status on a device comes from what the device actually returned
(see `status_of`). A metric a device does not implement is "unsupported", never 0.

Per-device metric status:
    healthy         collected on the last attempt and fresh
    unavailable     collected before, missing on the last attempt (e.g. a sensor or PSU removed, a table emptied)
    unsupported     the device has never returned it (noSuchObject / empty table)
    failed          the last attempt raised an error (timeout, authorisation, protocol)
    stale           last success older than 3 × the group's interval (polls not running or the group keeps failing)
    not_configured  the group is disabled for this switch, or needs device configuration (e.g. SNMPv3 VLAN contexts)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# collection groups and default intervals (seconds). 0 disables a group for a switch.
GROUPS: dict[str, dict] = {
    "system": {"interval": 60, "label": "System and reachability"},
    "interfaces": {"interval": 60, "label": "Interfaces and traffic"},
    "cpu_memory": {"interval": 60, "label": "CPU and memory"},
    "environment": {"interval": 300, "label": "Temperature, fans, power supplies"},
    "stack": {"interval": 300, "label": "Stack / chassis"},
    "poe": {"interval": 300, "label": "Power over Ethernet"},
    "lacp": {"interval": 300, "label": "Link aggregation / LACP"},
    "stp": {"interval": 300, "label": "Spanning tree"},
    "vlans": {"interval": 900, "label": "VLANs and port membership"},
    "mac_table": {"interval": 900, "label": "MAC address table"},
    "routing": {"interval": 300, "label": "Layer 3 and routing"},
    "neighbors": {"interval": 300, "label": "LLDP / CDP neighbors (topology)"},
    "inventory": {"interval": 3600, "label": "Hardware inventory"},
    "storage": {"interval": 300, "label": "Disks, flash and file systems"},
    "vendor_health": {"interval": 300, "label": "Vendor health: HA, VPN, SD-WAN, sessions, chassis alarms"},
    "custom": {"interval": 300, "label": "Custom OIDs (administrator-defined)"},
    # wireless controller groups (role "wlc" only; app/wireless)
    "wireless_ap": {"interval": 60, "label": "Wireless: access points", "wlc": True},
    "wireless_radio": {"interval": 60, "label": "Wireless: radios and channel utilisation", "wlc": True},
    "wireless_radio_rf": {"interval": 300, "label": "Wireless: noise and 802.11 interference", "wlc": True},
    "wireless_client": {"interval": 120, "label": "Wireless: clients", "wlc": True},
    "wireless_wlan": {"interval": 600, "label": "Wireless: WLANs / SSIDs", "wlc": True},
    "wireless_ap_cdp": {"interval": 900, "label": "Wireless: AP uplink neighbours (CDP)", "wlc": True},
    "wireless_radio_meta": {"interval": 900, "label": "Wireless: radio configuration, regulatory domain, RRM recommendation", "wlc": True},
    "wireless_rf_neighbors": {"interval": 300, "label": "Wireless: RRM neighbour radios (RF proximity)", "wlc": True},
}
WLC_GROUPS = [g for g, d in GROUPS.items() if d.get("wlc")]


VENDOR_KEYS = ("cisco", "fortinet", "juniper", "ruckus")


@dataclass(frozen=True)
class Metric:
    key: str
    group: str
    category: str
    source: str               # MIB (or "derived")
    oid: str
    dtype: str                # gauge | counter | state | info | table
    unit: str = ""
    vendors: tuple = ("cisco", "fortinet", "juniper", "ruckus", "generic")
    note: str = ""


M = Metric
METRICS: list[Metric] = [
    # system
    M("switch_up", "system", "availability", "SNMPv2-MIB", "1.3.6.1.2.1.1.3.0", "state", "", note="1 when the switch answered the poll"),
    M("switch_uptime_seconds", "system", "availability", "SNMPv2-MIB sysUpTime", "1.3.6.1.2.1.1.3.0", "gauge", "s",
      note="SNMP agent uptime; a decrease is reported as a restart"),
    M("switch_system_info", "system", "identity", "SNMPv2-MIB sysDescr/sysObjectID/sysName", "1.3.6.1.2.1.1", "info"),
    # interfaces
    M("switch_interface_status", "interfaces", "interfaces", "IF-MIB ifAdminStatus/ifOperStatus", "1.3.6.1.2.1.2.2.1.7/8", "state"),
    M("switch_interface_octets_hc", "interfaces", "traffic", "IF-MIB ifHCInOctets/ifHCOutOctets (64-bit)", "1.3.6.1.2.1.31.1.1.1.6/10", "counter", "bytes"),
    M("switch_interface_octets_32", "interfaces", "traffic", "IF-MIB ifInOctets/ifOutOctets (32-bit fallback)", "1.3.6.1.2.1.2.2.1.10/16", "counter", "bytes"),
    M("switch_interface_packets", "interfaces", "traffic", "IF-MIB ifHC*UcastPkts / Multicast / Broadcast", "1.3.6.1.2.1.31.1.1.1.7-13", "counter", "packets"),
    M("switch_interface_errors", "interfaces", "errors", "IF-MIB ifInErrors/ifOutErrors", "1.3.6.1.2.1.2.2.1.14/20", "counter", "packets"),
    M("switch_interface_discards", "interfaces", "errors", "IF-MIB ifInDiscards/ifOutDiscards", "1.3.6.1.2.1.2.2.1.13/19", "counter", "packets"),
    M("switch_interface_speed", "interfaces", "interfaces", "IF-MIB ifHighSpeed / ifSpeed", "1.3.6.1.2.1.31.1.1.1.15", "gauge", "bps"),
    M("switch_interface_alias", "interfaces", "interfaces", "IF-MIB ifAlias (description)", "1.3.6.1.2.1.31.1.1.1.18", "info"),
    M("switch_interface_duplex", "interfaces", "interfaces", "EtherLike-MIB dot3StatsDuplexStatus", "1.3.6.1.2.1.10.7.2.1.19", "state"),
    M("switch_interface_fcs_errors", "interfaces", "errors", "EtherLike-MIB dot3StatsFCSErrors", "1.3.6.1.2.1.10.7.2.1.3", "counter", "frames"),
    M("switch_interface_crc_errors", "interfaces", "errors", "OLD-CISCO-INTERFACES-MIB locIfInCRC", "1.3.6.1.4.1.9.2.2.1.1.12", "counter", "frames", ("cisco",)),
    M("switch_interface_resets", "interfaces", "errors", "OLD-CISCO-INTERFACES-MIB locIfResets", "1.3.6.1.4.1.9.2.2.1.1.17", "counter", "", ("cisco",)),
    M("switch_interface_carrier_transitions", "interfaces", "errors", "OLD-CISCO-INTERFACES-MIB locIfCarrierTransitions",
      "1.3.6.1.4.1.9.2.2.1.1.21", "counter", "", ("cisco",)),
    M("switch_interface_counter_discontinuity", "interfaces", "traffic", "IF-MIB ifCounterDiscontinuityTime", "1.3.6.1.2.1.31.1.1.1.19", "state",
      note="when present, a change invalidates the previous counter sample"),
    # cpu / memory
    M("switch_cpu_utilization_percent", "cpu_memory", "health", "CISCO-PROCESS-MIB cpmCPUTotal1minRev", "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "gauge", "%", ("cisco",)),
    M("switch_memory_utilization_percent", "cpu_memory", "health", "CISCO-PROCESS-MIB cpmCPUMemoryHCUsed/HCFree, "
      "CISCO-ENHANCED-MEMPOOL-MIB, CISCO-MEMORY-POOL-MIB (first that answers)", "1.3.6.1.4.1.9.9.109.1.1.1.1.17", "gauge", "%", ("cisco",)),
    M("switch_cpu_utilization_percent", "cpu_memory", "health", "FOUNDRY-SN-AGENT-MIB snAgentCpuUtilPercent / snAgGblCpuUtil1MinAvg",
      "1.3.6.1.4.1.1991.1.1.2.11.1.1.5", "gauge", "%", ("ruckus",)),
    M("switch_memory_utilization_percent", "cpu_memory", "health", "FOUNDRY-SN-AGENT-MIB snAgGblDynMemUtil/Total/Free",
      "1.3.6.1.4.1.1991.1.1.2.1.53", "gauge", "%", ("ruckus",)),
    # environment
    M("switch_temperature_celsius", "environment", "environment", "CISCO-ENVMON-MIB ciscoEnvMonTemperatureStatusTable, CISCO-ENTITY-SENSOR-MIB (fallback)",
      "1.3.6.1.4.1.9.9.13.1.3.1", "gauge", "°C", ("cisco",)),
    M("switch_fan_status", "environment", "environment", "CISCO-ENVMON-MIB ciscoEnvMonFanStatusTable", "1.3.6.1.4.1.9.9.13.1.4.1", "state", "", ("cisco",)),
    M("switch_psu_status", "environment", "environment", "CISCO-ENVMON-MIB ciscoEnvMonSupplyStatusTable", "1.3.6.1.4.1.9.9.13.1.5.1", "state", "", ("cisco",)),
    M("switch_temperature_celsius", "environment", "environment", "FOUNDRY-SN-AGENT-MIB snAgentTemp2Table / snAgentTempTable / snChasActualTemperature",
      "1.3.6.1.4.1.1991.1.1.2.13.3.1", "gauge", "°C", ("ruckus",), "reported in 0.5 °C steps"),
    M("switch_fan_status", "environment", "environment", "FOUNDRY-SN-AGENT-MIB snChasFan2Table / snChasFanTable", "1.3.6.1.4.1.1991.1.1.1.3.2.1", "state", "", ("ruckus",)),
    M("switch_psu_status", "environment", "environment", "FOUNDRY-SN-AGENT-MIB snChasPwrSupply2Table / snChasPwrSupplyTable", "1.3.6.1.4.1.1991.1.1.1.2.2.1",
      "state", "", ("ruckus",)),
    # standard host / sensor MIBs: the only source on generic devices, the fallback on Cisco / Ruckus
    M("switch_cpu_utilization_percent", "cpu_memory", "health", "HOST-RESOURCES-MIB hrProcessorLoad (average) / UCD-SNMP-MIB ssCpuIdle",
      "1.3.6.1.2.1.25.3.3.1.2", "gauge", "%", ("generic",)),
    M("switch_memory_utilization_percent", "cpu_memory", "health", "UCD-SNMP-MIB memTotalReal/memAvailReal (+buffers, cached) / HOST-RESOURCES-MIB hrStorageRam",
      "1.3.6.1.4.1.2021.4", "gauge", "%", ("generic",)),
    M("switch_load_average", "cpu_memory", "health", "UCD-SNMP-MIB laLoad (1 / 5 / 15 min)", "1.3.6.1.4.1.2021.10.1.3", "gauge", "",
      ("generic",), "Unix-like agents (net-snmp) only"),
    M("switch_temperature_celsius", "environment", "environment", "ENTITY-SENSOR-MIB entPhySensorTable (type celsius)", "1.3.6.1.2.1.99.1.1.1",
      "gauge", "°C", ("generic",)),
    M("switch_sensor_value", "environment", "environment", "ENTITY-SENSOR-MIB entPhySensorTable (voltage, current, power, fan rpm, humidity)",
      "1.3.6.1.2.1.99.1.1.1", "gauge", "", note="scaled by entPhySensorScale / Precision; also asked of Cisco / Ruckus when their MIB has no temperatures"),
    M("switch_storage_used_percent", "storage", "health", "HOST-RESOURCES-MIB hrStorageTable (fixed / flash / network disks)", "1.3.6.1.2.1.25.2.3.1",
      "gauge", "%", note="RAM and virtual memory are reported under memory, not storage"),
    # Fortinet (FORTINET-FORTIGATE-MIB / FORTINET-FORTISWITCH-MIB)
    M("switch_cpu_utilization_percent", "cpu_memory", "health", "FORTINET-FORTIGATE-MIB fgSysCpuUsage + fgProcessorTable / FORTINET-FORTISWITCH-MIB fsSysCpuUsage",
      "1.3.6.1.4.1.12356.101.4.1.3.0", "gauge", "%", ("fortinet",)),
    M("switch_memory_utilization_percent", "cpu_memory", "health", "FORTINET-FORTIGATE-MIB fgSysMemUsage / FORTINET-FORTISWITCH-MIB fsSysMemUsage",
      "1.3.6.1.4.1.12356.101.4.1.4.0", "gauge", "%", ("fortinet",)),
    M("switch_temperature_celsius", "environment", "environment", "FORTINET-FORTIGATE-MIB fgHwSensorTable (temperature sensors)", "1.3.6.1.4.1.12356.101.4.3.2.1",
      "gauge", "°C", ("fortinet",), "hardware models only (no sensors on VMs); FortiSwitch falls back to ENTITY-SENSOR-MIB"),
    M("switch_fan_status", "environment", "environment", "FORTINET-FORTIGATE-MIB fgHwSensorTable (fan sensors, alarm status)", "1.3.6.1.4.1.12356.101.4.3.2.1.4",
      "state", "", ("fortinet",)),
    M("switch_psu_status", "environment", "environment", "FORTINET-FORTIGATE-MIB fgHwSensorTable (PSU sensors, alarm status)", "1.3.6.1.4.1.12356.101.4.3.2.1.4",
      "state", "", ("fortinet",)),
    M("fortigate_sessions", "vendor_health", "security", "FORTINET-FORTIGATE-MIB fgSysSesCount", "1.3.6.1.4.1.12356.101.4.1.8.0", "gauge", "sessions", ("fortinet",),
      "FortiGate only"),
    M("fortigate_ha_state", "vendor_health", "availability", "FORTINET-FORTIGATE-MIB fgHaSystemMode + fgHaStatsTable (sync status)", "1.3.6.1.4.1.12356.101.13",
      "state", "", ("fortinet",)),
    M("fortigate_vpn_tunnels", "vendor_health", "vpn", "FORTINET-FORTIGATE-MIB fgVpnTunTable (status, octets)", "1.3.6.1.4.1.12356.101.12.2.2.1", "table", "",
      ("fortinet",), "IPsec phase-2 selectors; SSL-VPN is not in this table"),
    M("fortigate_sdwan_health", "vendor_health", "wan", "FORTINET-FORTIGATE-MIB fgVWLHealthCheckLinkTable", "1.3.6.1.4.1.12356.101.4.9.2.1", "table", "",
      ("fortinet",), "FortiOS 6.2+ with SD-WAN health checks configured"),
    # Juniper (JUNIPER-MIB / JUNIPER-ALARM-MIB / JUNIPER-SRX5000-SPU-MONITORING-MIB)
    M("switch_cpu_utilization_percent", "cpu_memory", "health", "JUNIPER-MIB jnxOperatingCPU (Routing Engine rows)", "1.3.6.1.4.1.2636.3.1.13.1.8", "gauge", "%",
      ("juniper",)),
    M("switch_memory_utilization_percent", "cpu_memory", "health", "JUNIPER-MIB jnxOperatingBuffer (Routing Engine rows)", "1.3.6.1.4.1.2636.3.1.13.1.11", "gauge", "%",
      ("juniper",)),
    M("switch_temperature_celsius", "environment", "environment", "JUNIPER-MIB jnxOperatingTemp", "1.3.6.1.4.1.2636.3.1.13.1.7", "gauge", "°C", ("juniper",)),
    M("switch_fan_status", "environment", "environment", "JUNIPER-MIB jnxOperatingState (fan rows)", "1.3.6.1.4.1.2636.3.1.13.1.6", "state", "", ("juniper",)),
    M("switch_psu_status", "environment", "environment", "JUNIPER-MIB jnxOperatingState (PEM / power supply rows)", "1.3.6.1.4.1.2636.3.1.13.1.6", "state", "",
      ("juniper",)),
    M("juniper_chassis_alarms", "vendor_health", "hardware", "JUNIPER-ALARM-MIB jnxYellowAlarms / jnxRedAlarms", "1.3.6.1.4.1.2636.3.4.2", "state", "", ("juniper",)),
    M("srx_flow_sessions", "vendor_health", "security", "JUNIPER-SRX5000-SPU-MONITORING-MIB jnxJsSPUMonitoringCurrentFlowSession", "1.3.6.1.4.1.2636.3.39.1.12.1.1.1.6",
      "gauge", "sessions", ("juniper",), "SRX only"),
    # administrator-defined
    M("custom_oid_values", "custom", "custom", "Custom OID profiles (SnmpCustomOid)", "", "gauge", "", note="only devices a custom OID applies to"),
    # stack
    M("switch_stack_members", "stack", "hardware", "CISCO-STACKWISE-MIB cswSwitchInfoTable", "1.3.6.1.4.1.9.9.500.1.2.1.1", "table", "", ("cisco",),
      "only on StackWise-capable platforms"),
    M("switch_stack_ring", "stack", "hardware", "CISCO-STACKWISE-MIB cswRingRedundant / cswStackPortInfoTable", "1.3.6.1.4.1.9.9.500.1.1.3.0", "state", "", ("cisco",)),
    M("switch_stack_members", "stack", "hardware", "FOUNDRY-SN-STACKING-MIB snStackingOperUnitTable", "1.3.6.1.4.1.1991.1.1.3.31.2.2.1", "table", "", ("ruckus",)),
    # PoE
    M("switch_poe_budget_watts", "poe", "poe", "POWER-ETHERNET-MIB pethMainPsePower / ConsumptionPower", "1.3.6.1.2.1.105.1.3.1.1", "gauge", "W"),
    M("switch_poe_port_status", "poe", "poe", "POWER-ETHERNET-MIB pethPsePortTable", "1.3.6.1.2.1.105.1.1.1", "state"),
    M("switch_poe_port_power_watts", "poe", "poe", "CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortPwrConsumption/Allocated", "1.3.6.1.4.1.9.9.402.1.2.1",
      "gauge", "W", ("cisco",), "port mapped to the interface by name (switch/module/port)"),
    M("switch_poe_port_power_watts", "poe", "poe", "FOUNDRY-SN-AGENT-MIB snAgentPoePortTable", "1.3.6.1.4.1.1991.1.1.2.14.2.2.1", "gauge", "W", ("ruckus",)),
    M("switch_poe_unit_budget", "poe", "poe", "FOUNDRY-SN-AGENT-MIB snAgentPoeUnitTable", "1.3.6.1.4.1.1991.1.1.2.14.4.1.1", "gauge", "W", ("ruckus",)),
    # LACP
    M("switch_lacp_member_state", "lacp", "lacp", "IEEE8023-LAG-MIB dot3adAggPortTable", "1.2.840.10006.300.43.1.2.1.1", "state"),
    M("switch_channel_membership", "lacp", "lacp", "CISCO-PAGP-MIB pagpGroupIfIndex (static / PAgP / LACP)", "1.3.6.1.4.1.9.9.98.1.1.1.1.8", "state", "", ("cisco",)),
    # STP
    M("switch_stp_bridge", "stp", "stp", "BRIDGE-MIB dot1dStp (root, root port, topology changes)", "1.3.6.1.2.1.17.2", "state"),
    M("switch_stp_ports", "stp", "stp", "BRIDGE-MIB dot1dStpPortTable", "1.3.6.1.2.1.17.2.15.1", "state"),
    M("switch_stp_mode", "stp", "stp", "CISCO-STP-EXTENSIONS-MIB stpxSpanningTreeType", "1.3.6.1.4.1.9.9.82.1.6.1.0", "info", "", ("cisco",)),
    M("switch_stp_mode", "stp", "stp", "RSTP-MIB dot1dStpVersion", "1.3.6.1.2.1.17.2.16.0", "info", "", ("fortinet", "juniper", "ruckus", "generic")),
    M("switch_stp_per_vlan", "stp", "stp", "BRIDGE-MIB per VLAN (community@vlan / SNMPv3 context vlan-N)", "1.3.6.1.2.1.17.2", "state", "", ("cisco",),
      "PVST+: needs per-VLAN SNMP contexts on SNMPv3 (snmp-server group ... context vlan- match prefix)"),
    # VLANs
    M("switch_vlan_info", "vlans", "vlans", "CISCO-VTP-MIB vtpVlanTable", "1.3.6.1.4.1.9.9.46.1.3.1.1", "table", "", ("cisco",)),
    M("switch_vlan_membership", "vlans", "vlans", "CISCO-VLAN-MEMBERSHIP-MIB vmVlan + CISCO-VTP-MIB vlanTrunkPortTable", "1.3.6.1.4.1.9.9.68.1.2.2.1.2",
      "table", "", ("cisco",)),
    M("switch_vlan_info", "vlans", "vlans", "Q-BRIDGE-MIB dot1qVlanStaticTable", "1.3.6.1.2.1.17.7.1.4.3.1", "table", "", ("fortinet", "juniper", "ruckus", "generic")),
    M("switch_vlan_membership", "vlans", "vlans", "Q-BRIDGE-MIB egress/untagged port lists + dot1qPvid", "1.3.6.1.2.1.17.7.1.4.3.1.2", "table", "",
      ("fortinet", "juniper", "ruckus", "generic")),
    # MAC table
    M("switch_mac_table", "mac_table", "mac", "BRIDGE-MIB dot1dTpFdbTable per VLAN (community@vlan / context vlan-N)", "1.3.6.1.2.1.17.4.3.1", "table", "",
      ("cisco",), "needs per-VLAN SNMP contexts on SNMPv3"),
    M("switch_mac_table", "mac_table", "mac", "Q-BRIDGE-MIB dot1qTpFdbTable (BRIDGE-MIB fallback)", "1.3.6.1.2.1.17.7.1.2.2.1", "table", "", ("fortinet", "juniper", "ruckus", "generic")),
    # routing
    M("switch_ip_interfaces", "routing", "routing", "IP-MIB ipAddrTable", "1.3.6.1.2.1.4.20.1", "table"),
    M("switch_route_count", "routing", "routing", "IP-FORWARD-MIB inetCidrRouteNumber / ipCidrRouteNumber", "1.3.6.1.2.1.4.24.6.0", "gauge"),
    M("switch_ospf_neighbors", "routing", "routing", "OSPF-MIB ospfNbrTable", "1.3.6.1.2.1.14.10.1", "table"),
    M("switch_bgp_peers", "routing", "routing", "BGP4-MIB bgpPeerTable", "1.3.6.1.2.1.15.3.1", "table"),
    # neighbors / topology
    M("switch_lldp_neighbors", "neighbors", "topology", "LLDP-MIB (IEEE 802.1AB) lldpRemTable + lldpRemManAddrTable + lldpLocPortTable",
      "1.0.8802.1.1.2.1.4.1.1", "table", note="LLDP must be enabled on the switch (lldp run / lldp enable)"),
    M("switch_cdp_neighbors", "neighbors", "topology", "CISCO-CDP-MIB cdpCacheTable", "1.3.6.1.4.1.9.9.23.1.2.1.1", "table", "", ("cisco",)),
    # inventory
    M("switch_inventory", "inventory", "hardware", "ENTITY-MIB entPhysicalTable", "1.3.6.1.2.1.47.1.1.1.1", "table"),
    M("switch_firmware_version", "inventory", "identity", "sysDescr (Cisco) / FOUNDRY-SN-AGENT-MIB snAgImgVer (Ruckus)", "1.3.6.1.4.1.1991.1.1.2.1.11.0",
      "info"),
]


def _wireless_metrics() -> list[Metric]:
    from ..wireless.oids import OBJ
    seen: dict[str, Metric] = {}
    for n, o in OBJ.items():
        if o["metric"] and o["metric"] not in seen:
            srcs = sorted({x["mib"] for x in OBJ.values() if x["metric"] == o["metric"]})
            seen[o["metric"]] = Metric(o["metric"], o["group"], "wireless_" + o["category"], " / ".join(srcs) + f" {n}", o["oid"],
                                       "gauge" if o["unit"] else "state", o["unit"], ("cisco",), o["note"])
    return list(seen.values())


METRICS += _wireless_metrics()


def metrics_for(vendor: str) -> list[Metric]:
    v = vendor if vendor in VENDOR_KEYS else "generic"
    return [m for m in METRICS if v in m.vendors]


@dataclass
class Outcome:
    """What one poll learned about each metric: ok / missing / error / not_configured, plus row counts."""
    results: dict[str, dict] = field(default_factory=dict)

    def ok(self, key: str, rows: int = 1, source: str = ""):
        cur = self.results.get(key)
        if cur and cur["result"] == "ok":
            cur["rows"] += rows
            return
        self.results[key] = {"result": "ok", "rows": rows, "source": source}

    def missing(self, key: str, *_ignored, why: str = "not returned by the device (noSuchObject / empty table)"):
        # extra positional args (row count, source) are accepted so `(o.ok if x else o.missing)(key, n, src)` works
        if key not in self.results:
            self.results[key] = {"result": "missing", "reason": why}

    def error(self, key: str, msg: str):
        if self.results.get(key, {}).get("result") != "ok":
            self.results[key] = {"result": "error", "reason": msg[:300]}

    def not_configured(self, key: str, why: str):
        if self.results.get(key, {}).get("result") != "ok":
            self.results[key] = {"result": "not_configured", "reason": why}


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def merge_capabilities(prev: dict | None, outcome: Outcome, groups_run: set[str], now: datetime, vendor: str,
                       intervals: dict[str, int]) -> dict:
    """Fold one poll's outcome into the stored per-metric capability record."""
    caps = {k: dict(v) for k, v in (prev or {}).items()}
    for m in metrics_for(vendor):
        rec = caps.setdefault(m.key, {"group": m.group, "ever_ok": False, "last_success": None, "last_error": None,
                                      "last_attempt": None, "last_result": None, "reason": "", "source": m.source})
        rec["group"] = m.group
        if m.group not in intervals:      # group not applicable to this device (wireless groups on a plain switch)
            caps.pop(m.key, None)
            continue
        if intervals.get(m.group, 1) == 0:
            rec.update(last_result="not_configured", reason="collection disabled for this switch")
            continue
        if m.group not in groups_run:
            continue
        r = outcome.results.get(m.key)
        if r is None:
            continue
        rec["last_attempt"] = now.isoformat()
        rec["last_result"] = r["result"]
        if r["result"] == "ok":
            rec.update(ever_ok=True, last_success=now.isoformat(), reason="", rows=r.get("rows", 1))
            if r.get("source"):
                rec["source"] = r["source"]
        else:
            rec["reason"] = r.get("reason", "")
            if r["result"] == "error":
                rec["last_error"] = {"at": now.isoformat(), "message": r.get("reason", "")}
    return caps


def status_of(rec: dict, now: datetime, interval: int) -> str:
    res = rec.get("last_result")
    if res is None:
        return "not_configured" if interval == 0 else "stale" if rec.get("ever_ok") else "pending"
    if res == "not_configured":
        return "not_configured"
    if res == "error":
        return "failed"
    if res == "missing":
        return "unavailable" if rec.get("ever_ok") else "unsupported"
    last = _aware(rec.get("last_success"))
    if last and interval and (now - last).total_seconds() > 3 * interval + 60:
        return "stale"
    return "healthy"


def coverage(caps: dict, now: datetime, intervals: dict[str, int]) -> dict:
    """Coverage = healthy / metrics the device supports (healthy + unavailable + failed + stale). Unsupported and
    not-configured metrics are counted separately: a switch without PoE is not "less covered" for lacking PoE."""
    counts: dict[str, int] = {}
    for rec in caps.values():
        st = status_of(rec, now, intervals.get(rec.get("group", ""), 60))
        counts[st] = counts.get(st, 0) + 1
    supported = sum(counts.get(k, 0) for k in ("healthy", "unavailable", "failed", "stale"))
    pct = round(100.0 * counts.get("healthy", 0) / supported, 1) if supported else None
    return {"percent": pct, "counts": counts, "supported": supported, "defined": len(caps)}


def describe(caps: dict, vendor: str, now: datetime, intervals: dict[str, int]) -> list[dict]:
    """Capability page rows: one per registry metric for this vendor, with status and reason."""
    out = []
    seen = set()
    for m in metrics_for(vendor):
        if m.key in seen:
            continue
        seen.add(m.key)
        if m.group not in intervals:
            continue
        rec = caps.get(m.key) or {}
        iv = intervals.get(m.group, GROUPS[m.group]["interval"])
        st = status_of(rec, now, iv) if rec else ("not_configured" if iv == 0 else "pending")
        out.append({"metric": m.key, "group": m.group, "group_label": GROUPS[m.group]["label"], "category": m.category,
                    "source": rec.get("source") or m.source, "oid": m.oid, "type": m.dtype, "unit": m.unit, "interval_seconds": iv,
                    "status": st, "reason": rec.get("reason", ""), "last_success": rec.get("last_success"),
                    "last_attempt": rec.get("last_attempt"), "last_error": rec.get("last_error"), "rows": rec.get("rows"), "note": m.note,
                    "vendors": list(m.vendors)})
    return out
