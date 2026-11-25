# Sentinel NMS feature matrix

**Before** is the state at assessment on 2026-11-20; **after** is the state at the end of this release.

Statuses:
- `IMPLEMENTED`
- `PARTIALLY_IMPLEMENTED`
- `UI_ONLY`
- `BACKEND_ONLY`
- `NOT_IMPLEMENTED`
- `BROKEN`
- `NEEDS_VALIDATION`: built and tested against simulators only, not real or lab hardware.

No feature was found `UI_ONLY` or `BROKEN`: every NMS page checked calls real APIs backed by stored data.

## Discovery and inventory

| Feature | Before | After | Evidence |
|---|---|---|---|
| SNMPv2c / v3 discovery and polling | IMPLEMENTED | IMPLEMENTED | `switches/discovery.py`, `poller.py`, `test_switches.py`, `test_snmp.py` |
| SNMPv1 | NOT_IMPLEMENTED | NOT_IMPLEMENTED (by design: no HC counters; v1 traps accepted) | SNMP.md §14 |
| Subnet / range discovery, scheduled and on-demand | IMPLEMENTED (SNMP sweep, candidates only) | same | `SwitchDiscoveryRun`, `/api/switches/admin/discovery` |
| ICMP / TCP liveness discovery, ARP discovery | NOT_IMPLEMENTED | IMPLEMENTED (extensions) | [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §1 |
| LLDP / CDP neighbour discovery | IMPLEMENTED | IMPLEMENTED | `collect_neighbors`, topology |
| Manual registration, bulk import, CSV export | IMPLEMENTED | IMPLEMENTED | `POST /api/switches`, `/import`, `/export.csv` |
| Identity: vendor / model / serial / firmware / OS / type / role / location | IMPLEMENTED | IMPLEMENTED | `fingerprints.py`, ENTITY-MIB |
| Grouping by site / building / floor / vendor / model / role | IMPLEMENTED | IMPLEMENTED | `switches` columns, filters |
| Duplicate prevention (devices, discovery runs) | IMPLEMENTED | IMPLEMENTED | unique name / address; one run per network |

## Monitoring

| Feature | Before | After | Evidence |
|---|---|---|---|
| Interfaces: status, speed, duplex, traffic, errors, discards, CRC, flaps | IMPLEMENTED | IMPLEMENTED | `collect_interfaces`, `rates.py` |
| HC counters, rollover / reset / reboot detection | IMPLEMENTED | IMPLEMENTED | `rates.py`, tests |
| LAG / port-channel, VLAN, trunk / access, STP, PoE | IMPLEMENTED | IMPLEMENTED | collectors |
| Top-N, 95th percentile, availability, capacity forecast | IMPLEMENTED | IMPLEMENTED | `nms/analytics.py` |
| Hardware health and vendor alarms | IMPLEMENTED (Cisco / Fortinet / Juniper / Ruckus) | same | SNMP.md §5 |
| Aruba / HPE / Arista / Huawei / MikroTik / Dell / Extreme | PARTIALLY_IMPLEMENTED (standard MIBs) | same | VENDOR_SUPPORT_MATRIX.md |
| Juniper / Fortinet MIB coverage on real devices | NEEDS_VALIDATION | NEEDS_VALIDATION | fixtures only |
| Wireless 9800: controllers, APs, radios, clients, rogues, RF, history | IMPLEMENTED | IMPLEMENTED | WIRELESS.md |
| Ruckus SmartZone / One, Aruba Central, Mist wireless | NOT_IMPLEMENTED | IMPLEMENTED (extensions), NEEDS_VALIDATION against a real tenant | [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §6 |
| BGP peers / flaps, OSPF peers | IMPLEMENTED | IMPLEMENTED | `bgp.py`, routing collector |
| Routing tables / static routes | NOT_IMPLEMENTED (as data) | PARTIALLY_IMPLEMENTED (on demand via diagnostics: routing-table templates) | `ios.route`, `junos.route`, `fos.route` |
| WAN / ISP latency, loss, jitter, availability, SLA, SD-WAN | IMPLEMENTED | IMPLEMENTED | WAN.md |
| VPN / IPsec tunnels | IMPLEMENTED (FortiGate) | IMPLEMENTED | `vpnmon.py` |
| Service checks: TCP / HTTP / DNS / TLS expiry | IMPLEMENTED | IMPLEMENTED | `nms/services.py` |
| Flows (NetFlow / IPFIX / sFlow) | IMPLEMENTED | IMPLEMENTED | `flows/` |
| Topology L2 (LLDP / CDP), impact, dependency suppression | IMPLEMENTED | IMPLEMENTED | TOPOLOGY_DESIGN.md |
| Topology L3 / WAN layer | NOT_IMPLEMENTED | IMPLEMENTED (extensions) | [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §2 |
| Faults: correlation, root-cause suppression, maintenance, ack / assign | IMPLEMENTED | IMPLEMENTED | `alerts/engine.py`, `nms/maintenance.py` |
| NMS faults kept apart from SIEM incidents | IMPLEMENTED | IMPLEMENTED | `products.alert_product` |
| Self-monitoring (loop lag, poll freshness, SLOs) | IMPLEMENTED | IMPLEMENTED | `selfmon.py` |

## Configuration management

| Feature | Before | After | Evidence |
|---|---|---|---|
| Read-only SSH backup, versions, diff, change alert, host-key pinning | IMPLEMENTED (Cisco / Junos / ICX) | IMPLEMENTED (through the gateway dial) | `configs/backup.py`, `test_config_backup.py` |
| Configuration compliance | IMPLEMENTED | IMPLEMENTED | NETWORK_COMPLIANCE.md |
| Approved configuration changes for switches / routers | NOT_IMPLEMENTED | IMPLEMENTED (off by default), NEEDS_VALIDATION on hardware | `access/changes.py`, `test_change_workflow` |
| FortiGate changes (IaC) | IMPLEMENTED | IMPLEMENTED | IAC.md |
| Restore whole configuration | NOT_IMPLEMENTED | NOT_IMPLEMENTED (line-based rollback, Junos `rollback 1`) | roadmap R6 |

## Device access (mandatory core)

| Feature | Before | After | Evidence |
|---|---|---|---|
| Dedicated access gateway | NOT_IMPLEMENTED | IMPLEMENTED | `access/gateway.py`, compose `access` |
| Browser SSH terminal (xterm.js, WebSocket, resize, timeouts, multiple sessions, copy, download, reconnect) | NOT_IMPLEMENTED | IMPLEMENTED | `Terminal.tsx`, `terminal.py`, e2e test + browser check |
| Device Access tab | NOT_IMPLEMENTED | IMPLEMENTED | `DeviceAccessTab` |
| Credential vault (kinds, encryption, group assignment, rotation, RBAC) | PARTIALLY_IMPLEMENTED | IMPLEMENTED | `vault.py`, tests |
| Command library, 5-level risk classification | NOT_IMPLEMENTED | IMPLEMENTED (71 templates, 11 platforms) | `commands.py`, 36 classification tests |
| Diagnostics, bulk diagnostics (bounded, cancel, partial failure, history, export) | NOT_IMPLEMENTED | IMPLEMENTED | `diagnostics.py`, bulk test, 2,000-device simulation |
| Session management, termination, access audit (hash-chained) | NOT_IMPLEMENTED | IMPLEMENTED | `audit.py`, tests |
| Session recording (configurable) | NOT_IMPLEMENTED | IMPLEMENTED | `ACCESS_RECORDING` |
| HTTPS management | NOT_IMPLEMENTED | PARTIALLY_IMPLEMENTED (audited direct link, no proxy) | DEVICE_ACCESS_ARCHITECTURE.md §6 |
| NETCONF / RESTCONF | NOT_IMPLEMENTED | IMPLEMENTED (fixed read-only operations, extensions) | [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §3 |
| SNMP diagnostics | IMPLEMENTED (switch Test / Poll now) | IMPLEMENTED | `/api/switches/{id}/test` |
| Telnet (opt-in, off by default), serial console (Opengear, Cisco terminal server) | NOT_IMPLEMENTED | IMPLEMENTED (extensions) | [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §4–5 |
| Vendor access on real hardware | — | NEEDS_VALIDATION | VENDOR_SUPPORT_MATRIX.md |

## Security and RBAC

| Feature | Before | After |
|---|---|---|
| NMS roles (7) and permissions (13), enforced on REST and WebSocket | NOT_IMPLEMENTED | IMPLEMENTED |
| Site-scoped access | IMPLEMENTED (views) | IMPLEMENTED (views + access) |
| WebSocket origin + ticket authentication | — | IMPLEMENTED |
| SSRF prevention for device connections | IMPLEMENTED (`validate_address`) | IMPLEMENTED (single dial path) |

## Automation

| Feature | Before | After |
|---|---|---|
| Ansible (approved playbooks, separate runner) | NOT_IMPLEMENTED | IMPLEMENTED (extensions; [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §7) |
| Configuration templates with variables, scheduled change jobs | NOT_IMPLEMENTED | NOT_IMPLEMENTED (scheduled changes deliberately) |
| Bulk diagnostics as automation | — | IMPLEMENTED |
| Pre-checks / post-checks / dry run / approval / rollback | — | IMPLEMENTED in the change workflow (dry run on Junos only) |
