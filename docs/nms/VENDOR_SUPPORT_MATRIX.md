# Vendor support matrix

Validation levels, strongest first:
- **Production**: observed on the production deployment.
- **Simulated**: automated tests against simulated agents or devices built from the vendor's MIBs or CLI behaviour.
- **Implemented**: code and templates exist, but there is no device-level test.
- **None**: not supported.

Nothing in this table claims lab-hardware validation. This repository has no lab hardware.

## Monitoring (SNMP)

| Vendor / line | Identification | Health / interfaces / VLAN / LAG / PoE | Routing | Wireless | Validation |
|---|---|---|---|---|---|
| Cisco Catalyst 9200 / 9300 / 9400 / 9500, older Catalyst | exact (sysObjectID + sysDescr) | yes | BGP4 / OSPF (standard MIBs) | — | Production (Cisco switches polled in production), Simulated |
| Cisco Catalyst 9800 WLC | family | controller health | — | APs, radios, WLANs, clients, rogues, RF, client traps | Production (9800 polled), Simulated |
| Cisco ISR / ASR, Nexus | family | yes (Cisco + standard MIBs) | standard MIBs | — | Simulated |
| Fortinet FortiGate | exact | CPU / memory / sessions / HA / sensors; IPsec and SD-WAN tables | standard MIBs | — | Production (FortiGate via REST and SNMP), Simulated |
| Fortinet FortiSwitch | exact | yes | — | — | Simulated |
| Fortinet FortiAP / FortiManager | — | — | — | — | None (FortiManager is used by IaC only) |
| Juniper EX / QFX / MX / SRX | family | RE CPU / memory, chassis, alarms, SRX SPU | BGP4 / OSPF | — | Simulated |
| Juniper Mist | integration | — | — | APs, radios, WLANs, clients via the Mist API ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §6) | Simulated (API-shaped fixtures) |
| Ruckus ICX | exact | yes (stack, PoE) | — | — | Production (ICX polled), Simulated |
| Ruckus SmartZone / vSZ | identified (SNMP) + integration | standard MIBs | — | APs, radios, WLANs, clients via the public API | Simulated (API-shaped fixtures) |
| Ruckus One, Ruckus APs | — | — | — | — | None |
| Aruba, HPE, Arista, Huawei, MikroTik, Dell, Extreme | generic (standard MIBs) | IF-MIB, ENTITY, Q-BRIDGE, LLDP, POWER-ETHERNET where exposed | standard MIBs | — | Simulated (generic profile) |

Standard monitoring for any vendor:
- availability (ICMP + SNMP);
- IF-MIB interfaces with HC counters;
- LLDP neighbours;
- Q-BRIDGE VLANs and MAC table;
- ENTITY inventory;
- HOST-RESOURCES where exposed.

## Device access (this release)

| Platform | Command library | Terminal | Diagnostics | Change procedure | Validation |
|---|---|---|---|---|---|
| Cisco IOS / IOS-XE | 13 templates | yes | exec channel | `configure terminal` … `end`, optional `write memory` | Simulated (asyncssh IOS-like device: exec + interactive shell with configuration mode) |
| Cisco NX-OS | 9 | yes | exec | `configure terminal` … `end`, `copy running-config startup-config` | Implemented |
| Cisco Catalyst 9800 | 7 | yes | exec | — (no change procedure for WLC configuration) | Implemented |
| FortiOS | 9 | yes | exec | lines with their own `config … end` blocks | Implemented (classifier tests for every FortiOS template) |
| Junos | 9 | yes | exec | `configure private`, `show \| compare`, `commit confirmed`, verify, `commit`; rollback `rollback 1` | Implemented (procedure unit-tested; no simulated Junos CLI) |
| Ruckus ICX | 7 | yes | shell (prompt-driven, `skip-page-display`) | `configure terminal` … `end`, `write memory` | Implemented |
| Ruckus SmartZone / vSZ | 2 | yes | shell | — | Implemented |
| Aruba AOS-CX | 4 | yes | shell | — | Implemented (set the access platform by hand) |
| Arista EOS | 4 | yes | exec | `configure terminal` … `end` | Implemented (manual platform) |
| Huawei VRP | 4 | yes | shell | — | Implemented (manual platform) |
| MikroTik RouterOS | 3 | yes | exec | — | Implemented (manual platform) |

- **Platform detection:** platforms are derived from the SNMP identification (vendor / family / OS). Aruba, Arista,
  Huawei and MikroTik devices are identified as `generic` by SNMP: an administrator sets their access platform on the
  device (`PUT /api/nms/access/devices/{id}/platform`).
- **Version-specific commands:** commands that differ by release are noted on the template, for example FortiOS
  `sdwan health-check` versus `virtual-wan-link` before 6.4. A command the device does not know is reported per
  command as `unsupported`; the other commands still run.

## APIs (REST / NETCONF / RESTCONF / telemetry)

| Interface | Status |
|---|---|
| FortiGate REST | Production (firewall monitoring, policies, IaC) |
| PAN-OS XML API | Production module (firewalls) |
| FortiManager JSON-RPC | IaC only |
| NETCONF / RESTCONF | Fixed read-only operations (capabilities, running config, interfaces, YANG library, Junos RPCs; IOS-XE / OpenConfig paths). Simulated NETCONF server and mock RESTCONF only. |
| gNMI / model-driven telemetry | None |
| SmartZone / Ruckus One / Mist / Aruba Central REST | Wireless integrations, read-only (simulated against documented response shapes) |
| Ansible network collections | cisco.ios / nxos, junipernetworks.junos, arista.eos via the runner; `cisco.ios.ios_command` ran against a simulated IOS device |
