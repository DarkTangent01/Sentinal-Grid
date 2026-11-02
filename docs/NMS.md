# Sentinel NMS core: analytics, service checks, maintenance, dependencies

Sentinel NMS covers the same ground as LibreNMS and Zabbix for this estate (Cisco / Ruckus switches, Cisco 9800 WLCs, FortiGate
firewalls, ISP circuits, TACACS+). This page lists what the NMS core adds, how it works, and an honest feature comparison.

## What this release adds

| Area | What | Where |
|---|---|---|
| Any SNMP device | HOST-RESOURCES-MIB CPU (average of hrProcessorLoad) and disks / flash (hrStorage); UCD-SNMP memory (avail + buffers + cached), load average, ssCpuIdle; ENTITY-SENSOR-MIB temperatures, voltages, current, power, fan rpm and humidity. Generic devices use only these; Cisco / Ruckus fall back to them when their vendor MIB returns nothing | `app/switches/collect.py` (`std_cpu_memory`, `std_sensors`, `collect_storage`), new `storage` group (300 s) |
| Device dependencies | `switches.parent_id`. A device behind an unreachable parent gets no alert of its own; the parent's `switch_unreachable` alert lists it in `dependent_devices` | `app/switches/alerts.py` (`down_root`), Device Dependencies page |
| Maintenance windows | One-off or weekly (with weekdays, a local start time, a duration and an IANA time zone) for devices, sites or service checks, or all network alerts. New NMS alerts in scope are held back (counted as `maintenance` in the rule run); polling continues | `app/nms/maintenance.py`, hook in `upsert_detections` |
| Service checks | TCP connect, HTTP(S) GET (status ranges, body text), DNS A / AAAA (expected address), TLS certificate expiry. Results go to ClickHouse `service_results` (400 days) | `app/nms/services.py`, worker `service_loop` |
| Alert rules | `switch_storage_high`, `nms_service_down` (N consecutive failures), `nms_service_degraded` (slow / warning for N minutes), `nms_cert_expiry` (high within 7 days). All auto-resolve | `app/switches/alerts.py`, `app/nms/alerts.py` |
| Analytics | Device health score (explainable deductions), availability and SLA per device / site / service, capacity forecasting (linear trend, days to threshold, r² confidence) for interfaces, CPU, memory and storage, PoE headroom, top-N interfaces and devices, 95th percentile (nearest rank, max of in / out), inventory and lifecycle (firmware drift per model, uptime buckets, unused ports, port speeds), alert analytics (per day, noisiest rules, MTTR, flapping alerts) | `app/nms/analytics.py`, `/api/nms/analytics/*`, Network Analytics pages |

Data rules:
- A value that was never measured is null, never 0. A device with no samples has availability "—", and a check that could not measure latency stores NULL.
- TLS certificates are always verified, and no option skips verification. HTTP checks never follow redirects and cap the body read at 256 KB.
- Only administrators can create checks, windows and dependencies, and every change is audited. Checks probe only the targets an administrator entered.
- Nothing writes to a device: every SNMP request is a GET or GETBULK.

## API

`/api/nms` (product `nms`):
- `GET analytics/{availability,capacity,top/interfaces,top/devices,health,inventory,alerts,filters}`
- `GET|POST services`, `PUT|DELETE services/{id}`, `GET services/{id}/history`, `POST services/{id}/run`
- `GET|POST maintenance`, `PUT|DELETE maintenance/{id}`
- `GET dependencies`, `PUT dependencies/{id}`

Migrations: PostgreSQL `0025_nms_core` (adds `switches.parent_id`, `nms_maintenance` and `nms_services`); ClickHouse 14 (`service_results`).

## Comparison with LibreNMS and Zabbix

✅ = present in Sentinel NMS, ◐ = partial, ✗ = not yet.

| Capability | LibreNMS | Zabbix | Sentinel NMS |
|---|---|---|---|
| SNMP v2c / v3 polling, per-group intervals, capability tracking | ✅ | ✅ | ✅ (v2c off unless enabled; per-metric supported / unsupported / failed / stale status) |
| Auto-discovery by subnet | ✅ | ✅ | ✅ (authorised networks only) |
| Interfaces, errors, discards, 64-bit counters, wrap / reset handling | ✅ | ✅ | ✅ |
| CPU / memory / disks / sensors on any SNMP device | ✅ | ✅ | ✅ (this release) |
| Vendor health: environment, stack, PoE, STP, LACP, VLAN, MAC, routing neighbours | ✅ | ◐ (templates) | ✅ Cisco and Ruckus |
| LLDP / CDP neighbours and topology map | ✅ | ◐ | ✅ (switch topology and path check) |
| Wireless controller, AP, client and RF analytics | ◐ | ◐ | ✅ Cisco 9800 (RF engine, findings) |
| ICMP / WAN SLA monitoring, ISP incidents | ◐ | ✅ | ✅ |
| Firewall health, VPN, BGP | ◐ | ◐ | ✅ FortiGate |
| Service checks (TCP / HTTP / DNS / TLS expiry) | ✅ (Nagios plugins) | ✅ (simple / web checks) | ✅ (this release) |
| Maintenance windows | ✅ | ✅ | ✅ (this release) |
| Parent / child dependencies | ✅ | ✅ | ✅ (this release) |
| Alert rules, dedup, auto-resolve, notifications, incidents | ✅ | ✅ | ✅ |
| Availability / SLA reports | ✅ | ✅ | ✅ (this release) |
| 95th percentile / billing | ✅ | ◐ | ✅ (report; no invoicing) |
| Capacity forecasting (`timeleft`) | ✗ | ✅ | ✅ (this release) |
| Health score per device | ✗ | ✗ | ✅ (this release) |
| Firmware drift / unused ports / lifecycle | ◐ | ✗ | ✅ (this release) |
| TACACS+ AAA, policy analytics, IaC, config drift (firewalls) | ✗ | ✗ | ✅ |
| SNMP trap receiver (v1 / v2c / v3, informs) | ✅ | ✅ | ✅ (docs/SNMP.md; set TRAP_BIND_IP to expose UDP 162) |
| Multi-vendor adapters (Cisco, Fortinet, Juniper, Ruckus) and fingerprinting | ✅ | ✅ (templates) | ✅ (docs/SNMP.md support matrix) |
| Switch config backup / diff (Oxidized / RANCID) | ✅ (Oxidized) | ✗ | ◐ firewalls only (IaC backups) |
| NetFlow / sFlow traffic analysis | ◐ (plugin) | ✗ | ◐ firewall traffic logs; no flow collector |
| Weathermap / custom dashboards | ✅ | ✅ | ◐ fixed dashboards |
| Distributed pollers / proxies | ✅ | ✅ | ◐ sharded firewall pollers; single switch poller |
| Agent-based OS monitoring | ✗ | ✅ | ✗ (SNMP only, which is deliberate for network gear) |
| Custom templates / user-defined OIDs, MIB import, OID test | ◐ | ✅ | ✅ (versioned custom OIDs; MIB parser; read-only OID test) |

The next candidates, in order of value for this estate:
1. Switch configuration backup and diff, read-only, over SSH or TFTP.
2. A flow collector.
3. SmartZone and Catalyst 9800 RESTCONF API adapters (docs/SNMP.md §14).
