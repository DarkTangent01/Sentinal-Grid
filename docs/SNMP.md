# Sentinel NMS: multi-vendor SNMP monitoring framework

This page covers multi-vendor SNMP monitoring for Cisco, Fortinet, Juniper and Ruckus devices, plus any other device through the standard MIBs. It describes the architecture, the SNMP engine, device identification, the vendor adapters, the MIB / OID registry, traps, alerting, security, the API, configuration and deployment, and what is and is not supported.

## 1. Audit of what already existed (phase 0)

The framework extends the existing switch monitoring module (`backend/app/switches`). It adds no second poller, scheduler, inventory or metric store.

| Area | Existing implementation (reused) |
|---|---|
| SNMP library | pysnmp 7.1 asyncio, wrapped by `switches/snmp.py` `PysnmpClient`: GET, GETNEXT / GETBULK walks, multi-column walks, v2c and v3 (noAuthNoPriv / authNoPriv / authPriv, MD5 / SHA-1 / SHA-2 / DES / 3DES / AES-128/192/256), errors classified as timeout / auth / protocol, one engine per credential set, one request in flight per device. The client never sends SET. |
| Inventory | `switches` table: every SNMP device. Wireless controllers are rows with role `wlc`. Discovery sweeps only authorised subnets (`switch_networks`). |
| Credentials | `switch_credentials`: secrets sealed with the application key (`TokenCipher`), never returned by the API. SNMPv2c is refused unless `SWITCH_ALLOW_SNMPV2C` is set. |
| Scheduler | `poller.run_due`: DB leases plus the `_inflight` set prevent duplicate polls; a global concurrency semaphore; per-group intervals; wireless controllers polled in the background with their own time budget. |
| Storage | ClickHouse `switch_metrics` / `switch_if_samples` and their hourly roll-ups; PostgreSQL rows for live state, events, poll runs and capabilities. |
| Interfaces | IF-MIB with HC counters and a 32-bit fallback, EtherLike-MIB, and rate maths (`rates.py`) that handles wrap, reset, reboot, gaps and implausible values. |
| Health | CPU, memory, environment, stack, PoE, LACP, STP, VLAN, MAC, routing, LLDP / CDP and ENTITY-MIB inventory, through the Cisco and Ruckus adapters. |
| Capabilities | Registry of metrics (`registry.py`). Each metric's per-device status is recorded as healthy / unavailable / unsupported / failed / stale / not configured, and coverage is calculated from it. |
| Alerts | The shared alert engine, with deduplication, auto-resolve, notifications and incident correlation; plus the NMS maintenance windows and device dependencies. |
| Access | RBAC (admin / analyst) and product access (Grid / NMS). There was no site-level scoping. |

Gaps the framework fills: device identification only distinguished Cisco, Ruckus and generic devices; there were no Fortinet or Juniper adapters, no traps, no custom OIDs, no MIB import, no OID test, no backoff, no site scope and no support matrix.

## 2. Architecture

```
backend/app/switches/
  snmp.py          shared SNMP engine (client)                      unchanged API
  fingerprints.py  device fingerprint registry                      NEW
  collect.py       standard MIB groups, Cisco / Ruckus / Generic adapters, standard-MIB fallback
  adapters.py      adapter interface + registry, Fortinet and Juniper adapters, vendor_health and custom groups   NEW
  registry.py      metric registry (MIB, OID, type, unit, vendors, group / interval)
  poller.py        scheduling, leases, backoff, persistence, normalisation into switch_metrics
  alerts.py        device alert rules (incl. switch_vendor_condition)
backend/app/snmp_profiles.py   MIB / OID profile manager: MIB parser, custom OIDs, metric switches, OID test   NEW
backend/app/snmp_traps.py      trap / inform receiver (separate service)                                       NEW
backend/app/api/snmp.py        /api/snmp                                                                       NEW
frontend/src/pages/snmp/       SNMP Monitoring pages                                                           NEW
```

### Adapter interface

An adapter is a Python object registered with `adapters.register()`. It provides:
- `vendor`
- `families`
- `cpu_memory(ctx)`, `environment(ctx)` and `stack(ctx)`, which return the shared normalised shapes
- optionally `vendor_health(ctx)`, which returns vendor-specific state plus `alarms` normalised to `{key, severity, component, detail}`

The engine selects the adapter by the identified vendor; adding a vendor needs no change to the engine. Standard MIBs fill whatever a vendor MIB leaves empty (`collect._with_standard`).

### Collection groups

| Group | Default interval | Notes |
|---|---|---|
| system | the device's poll interval | sysDescr / sysObjectID / sysName / sysLocation / sysContact / sysUpTime, plus snmpEngineID (needed for SNMPv3 traps) |
| interfaces, cpu_memory | the device's poll interval | |
| environment, stack, poe, lacp, stp, routing, neighbors | 300 s | |
| storage | 300 s | |
| vendor_health | 300 s | |
| custom | 300 s | |
| vlans, mac_table | 900 s | |
| inventory | 3600 s | |
| wireless groups | various | wireless controllers only |

Each group can be overridden or disabled per device.

### Engine limits

- At most `SWITCH_MAX_CONCURRENT_POLLS` devices are polled at once (default 16), with one request in flight per device.
- GETBULK runs with 25 repetitions, and table columns are walked side by side.
- Time budgets: per group (90 s; 300 s for wireless groups) and per poll (240 s; 900 s for a wireless controller).
- A poll stops after two group timeouts.
- **Backoff:** a failing device keeps its normal cadence for 2 failures, then the interval doubles up to 15 minutes. Authentication failures back off from the first failure. During backoff the poller still writes one `switch_up = 0` sample per missed interval, so availability is never overstated.
- Every poll is recorded in `switch_poll_runs` with each group's result and duration and the request count.

## 3. Device identification (fingerprints.py)

Identification checks these in order:
1. **sysObjectID product subtree.** Examples: FortiGate `1.3.6.1.4.1.12356.101.1.*`, FortiSwitch `…12356.106.1.*`. Confidence: `exact`.
2. **Enterprise number.**

   | Enterprise | Vendor |
   |---|---|
   | 9 | Cisco |
   | 12356 | Fortinet |
   | 2636 | Juniper |
   | 1991 | Ruckus ICX (Foundry) |
   | 25053 | Ruckus wireless |

   Confidence: `vendor`.
3. **sysDescr patterns.** These only refine the family, OS and version within the vendor already known: Catalyst, Nexus, Catalyst 9800 WLC, ASA, ISR / ASR, FortiGate / FortiSwitch, EX / QFX / SRX / MX, ICX, SmartZone, Ruckus AP. Confidence: `family`. When there is no vendor sysObjectID, the description alone identifies the device with confidence `descr` (low).
4. **Unknown.** The device is treated as `generic` and gets baseline standard-MIB monitoring.

**Overrides.** Administrators can set a vendor and product line per device (`PUT /api/snmp/devices/{id}/profile`). The override applies from the next poll. If the device's own sysObjectID disagrees, the conflict appears on the vendor overview page.

## 4. Standard MIB profiles (any vendor)

- SNMPv2-MIB, SNMP-FRAMEWORK-MIB (snmpEngineID)
- IF-MIB (ifTable / ifXTable, HC counters), EtherLike-MIB
- ENTITY-MIB (inventory), ENTITY-SENSOR-MIB (temperature, voltage, current, power, fan rpm, humidity)
- HOST-RESOURCES-MIB (processors, storage), UCD-SNMP-MIB (memory, load, CPU idle)
- BRIDGE / Q-BRIDGE, POWER-ETHERNET, IEEE8023-LAG, IP-MIB, IP-FORWARD, OSPF, BGP4, LLDP

Each object's availability is recorded per device. ENTITY-STATE-MIB is not mapped.

Interface utilisation is calculated from counter deltas over measured elapsed time. A sample is flagged (and no rate is produced) when a 32-bit counter wraps, a counter is reset or the device rebooted (sysUpTime goes down / ifCounterDiscontinuityTime changes), the rate is implausible, or there is a gap. When an ifIndex is renumbered, the old row is marked absent and no delta is calculated across it.

## 5. Vendor adapters

| Vendor / line | Source | Collected |
|---|---|---|
| **Cisco** Catalyst / IE / Nexus / ISR | CISCO-PROCESS-MIB, CISCO-ENHANCED-MEMPOOL / MEMORY-POOL, CISCO-ENVMON / ENTITY-SENSOR, CISCO-STACKWISE, CISCO-POWER-ETHERNET-EXT, CISCO-VTP / VLAN-MEMBERSHIP, CISCO-STP-EXTENSIONS, CISCO-PAGP, CISCO-CDP, plus standard MIBs | CPU, memory, temperature, fans, PSUs, stack, PoE, VLANs, PVST (needs SNMPv3 VLAN contexts), LAG, MAC table, CDP |
| **Cisco** Catalyst 9800 WLC | AIRESPACE / CISCO-LWAPP MIBs as implemented by IOS XE 17.x (see WIRELESS.md); AireOS-only objects are not assumed | APs, radios, band / channel / width, utilisation, noise and interference, RRM neighbours, WLANs, clients. APs are monitored through the WLC only. |
| **Fortinet** FortiGate | FORTINET-FORTIGATE-MIB: fgSystemInfo, fgProcessorTable, fgHwSensorTable, fgHaSystemMode / fgHaStatsTable, fgVpnTunTable, fgVWLHealthCheckLinkTable | CPU (per core), memory, sessions, log disk, HA mode and sync per member, IPsec tunnel state and bytes, SD-WAN health-check state / latency / jitter / loss, temperature / fan / PSU / voltage sensors, firmware |
| **Fortinet** FortiSwitch | FORTINET-FORTISWITCH-MIB fsSystemInfo, plus standard MIBs | CPU, memory, interfaces, VLANs (Q-BRIDGE), PoE (POWER-ETHERNET), ENTITY-SENSOR temperatures where exposed. FortiGate tables are never requested from a FortiSwitch. |
| **Juniper** EX / QFX / SRX / MX | JUNIPER-MIB jnxOperatingTable, JUNIPER-ALARM-MIB, JUNIPER-SRX5000-SPU-MONITORING-MIB (SRX only), plus standard MIBs | Routing Engine CPU / memory (the primary RE drives the device value; a standby RE is listed), temperatures, fans, PEMs / PSUs, components down, red / yellow chassis alarms, SRX flow sessions, interfaces, VLANs / MAC (Q-BRIDGE), BGP4 / OSPF |
| **Ruckus** ICX | FOUNDRY-SN-AGENT / SWITCH-GROUP / STACKING MIBs, plus standard MIBs | CPU, memory, temperature, fans, PSUs, stack, PoE per port and unit, VLANs, MAC, LAG, STP |
| **Ruckus** SmartZone / standalone APs | identified only (enterprise 25053) | standard MIBs only. AP, radio and client data needs the SmartZone API (not implemented). |

**Vendor alarms** (`switch_vendor_condition`): HA member not in sync, IPsec tunnel down, SD-WAN member dead, Junos red alarm (critical), Junos yellow alarm (medium), and an FPC / PIC / RE / PEM / fan reported down. A transition becomes a `vendor_alarm` / `vendor_alarm_cleared` event, and the alert resolves itself when the condition clears.

## 6. MIB / OID registry and profile manager

- **Built-in registry.** Every metric records its key, group (and therefore interval), category, MIB object, OID, type (gauge / counter / state / info / table), unit, applicable vendors and notes. Administrators can turn a metric off; a group whose metrics are all off is not polled. `switch_up` and `switch_system_info` cannot be disabled.
- **Custom OIDs.** Read-only items: a GET of one scalar, or a walk of one table column. Each has a type, unit, scale and filters (vendor, product line, devices). They are polled in the `custom` group with the device's own credential and stored as `custom:<name>`; counters become per-second rates, and no rate is calculated across a reset. Every create, update, delete and rollback is a numbered version that can be restored.
- **MIB import.** The importer parses the module text into OBJECT-TYPE, OBJECT IDENTIFIER, NOTIFICATION-TYPE, MODULE-IDENTITY, OBJECT-IDENTITY and SMIv1 TRAP-TYPE assignments. It never executes or compiles a file. It resolves names against built-in roots and modules imported earlier, lists unresolved parents instead of guessing them, and rejects binary or headerless files and files over 2 MB. A re-import of a changed module creates a new version, and the previous version can be restored. Imported names label search results, OID tests and trap varbinds.
- **OID test** (administrators only, audited). Runs a GET or walk (up to 200 rows) against one device with its own credential profile. It shows the raw value, the type, the parsed value and the MIB name, and says plainly when the device does not implement the object.
- **Export.** `GET /api/snmp/export` returns custom OIDs, metric settings and the MIB module list as JSON, with no device data and no secrets.
- **Support matrix.** One column per vendor product line in the inventory, one row per metric. Each cell is one of:
  - *observed*: at least one device of that line has returned the metric
  - *implemented*: the adapter asks for it, but no device has answered yet
  - *unsupported*: every device asked answered noSuchObject or an empty table
  - *failing*: the requests return errors

  A metric is never shown as supported because a MIB file defines it or a test fixture contains it.

## 7. Normalised metrics

Common units:

| Measure | Unit |
|---|---|
| CPU, memory, storage, utilisation | % |
| Memory, storage | bytes |
| Temperature | °C |
| Bandwidth | bit/s |
| Uptime | seconds |
| Power | W |
| Signal | dBm |
| SNR | dB |

Metrics are stored in `switch_metrics` (metric, component, value). Vendor-specific values keep their own names: `switch_sessions`, `switch_vpn_tunnels_up/down`, `switch_sdwan_latency_ms` / `jitter_ms` / `loss_pct`, and `custom:*`.

Provenance and data quality:
- Each device's capability record keeps the MIB source that answered and the last success / attempt / error.
- The raw vendor values stay in the device health JSON (shown on the device page).
- Interface samples carry quality flags.
- A missing metric is stored as nothing (null or absent), never 0.

## 8. SNMP traps (service `traps`)

**Listener.** The service listens on UDP 1162 in the container, published as **162/udp** on `TRAP_BIND_IP`. That defaults to `127.0.0.1`, so nothing is exposed until you set it.

**Accepted messages:**
- SNMPv1 traps; v1 traps are translated per RFC 3584 and mapped back to their SMIv2 notification OID
- SNMPv2c traps and informs
- SNMPv3 traps and informs

**Authentication.**
- The source address must be an inventory device.
- The message must authenticate with that device's own credential profile: its community, or its SNMPv3 user.
- SNMPv3 traps use keys localised to the device's snmpEngineID, which the poller learns. SNMPv3 informs use the receiver's own engine.
- A valid credential that belongs to another device is rejected.
- Rejected messages are counted and dropped; they are never stored.

**Normalisation.** Each trap is normalised to device, vendor, trap OID / name, severity, component / ifIndex, summary and raw varbinds (OID, type, value, MIB name). The vendor parsers cover:
- coldStart, warmStart, linkDown, linkUp and authenticationFailure
- BGP4 bgpEstablished / bgpBackwardTransition and OSPF neighbour state change
- BRIDGE newRoot / topologyChange, ENTITY entConfigChange and the POWER-ETHERNET notifications
- Cisco ENVMON (shutdown, voltage, temperature, fan, redundant supply) and CONFIG-MAN
- Juniper jnxPowerSupply / jnxFan / jnxOverTemperature failure and OK

Any other notification is stored with severity `informational` and named from imported MIBs.

**Deduplication.** The same (device, trap, component) within 30 s is counted, not stored again.

**Storage.** Rows go to ClickHouse `snmp_traps` and are kept for 180 days.

**Alert rule `snmp_trap`:**
- It raises an alert at or above `min_severity` (default medium).
- A paired notification clears the alert, for example jnxFanOK after jnxFanFailure, or bgpEstablished after bgpBackwardTransition.
- An unpaired trap clears after `window_minutes` (default 60).
- linkDown is excluded by default, because `switch_port_down` already covers port state from polling.

**Configuring devices.** Point each device's trap host at the NMS address, and use the same credential profile the NMS polls the device with. Examples:
- Cisco IOS-XE: `snmp-server host <nms> version 3 priv <user>`
- FortiGate: `config system snmp user` → `set notify-hosts <nms>`
- Junos: `set snmp v3 target-address …`
- ICX: `snmp-server host <nms> version v3 auth <user>`

## 9. Alerts

| Need | Rule |
|---|---|
| Device unreachable | switch_unreachable (suppressed behind an unreachable parent) |
| Interface down / utilisation / errors / discards / flapping | switch_port_down, switch_if_utilization, switch_if_errors, switch_if_discards, switch_if_flapping |
| High CPU / memory / temperature / storage | switch_cpu_high, switch_memory_high, switch_temperature_high, switch_storage_high |
| Fan / PSU failure | switch_fan_failure, switch_psu_failure (all vendors with environment data) |
| PoE overload | switch_poe_budget |
| Routing peer down | switch_routing_neighbor (OSPF / BGP4 polling), snmp_trap (bgpBackwardTransition) |
| VPN down, HA, SD-WAN, Junos chassis alarms | switch_vendor_condition |
| Wireless AP down / radio failure | wireless_ap_down, wireless_radio_down |
| SNMP polling failure | switch_stale_metrics, switch_snmp_auth |
| Traps | snmp_trap |

Threshold rules use persistence (N consecutive samples). Stateful rules auto-resolve and send a recovery notification. Deduplication works through group keys. Maintenance windows and dependencies apply to all NMS rules.

## 10. Security

- **SNMPv3 preferred.** v2c is refused unless explicitly enabled, and SNMPv1 polling is not offered.
- **Credentials.** They are encrypted at rest and assigned per device. They are never returned by the API or written to logs or the frontend, and error messages never include communities or keys. Rotate a credential by editing its profile; every device that uses it picks up the change on the next poll.
- **Read-only.** The engine has no SET code path. The OID test and custom OIDs are GET / GETBULK only, and OIDs are validated as numeric dotted strings.
- **Polling sources.** Devices can only be added inside administrator-authorised subnets (`switch_networks`).
- **Uploaded MIBs.** They are parsed as text only, with size and binary checks.
- **RBAC.** Reads need NMS product access; changes need an administrator. Every change and every OID test is audited.
- **Site scope.** `users.sites`, edited under Settings → Users; empty means every site, and administrators are never scoped. It applies to `/api/snmp/*` and the switch inventory, detail, interface, MAC and event APIs; out-of-scope devices return 404. *Not yet scoped:* the switch topology map, the NMS analytics pages and the wireless pages.

## 11. API (`/api/snmp`, product NMS)

| Method | Path | Who |
|---|---|---|
| GET | vendors, polling-health?range, fingerprints, identify?sys_object_id&sys_descr | NMS users (site-scoped) |
| PUT | devices/{id}/profile `{vendor_override, family_override}` | admin |
| GET | registry?vendor&group&q, support-matrix, oids/search?q | NMS users |
| PUT | registry/{key} `{enabled}` | admin |
| POST | oids/test `{switch_id, oid, method: get|walk}` | admin |
| GET / POST / PUT / DELETE | custom, custom/{id}; GET custom/{id}/versions; POST custom/{id}/rollback/{version} | read: users, write: admin |
| GET / POST | mibs (POST `{filename, content}`), mibs/{id}; PUT mibs/{id} `{enabled}`; POST mibs/{id}/rollback; DELETE mibs/{id} | read: users, write: admin |
| GET | export, traps?range&switch_id&severity&q, stats | NMS users |

User site scope: `POST /api/users` and `PATCH /api/users/{id}` accept `sites: [...]`.

## 12. Configuration and deployment

**Migrations:**
- **PostgreSQL 0026** adds to `switches`: product_line, device_type, id_confidence, vendor_override, family_override, engine_id and backoff_until. It adds `users.sites`, and creates the tables snmp_custom_oids, snmp_profile_versions, snmp_mib_modules and snmp_metric_settings.
- **ClickHouse 15** creates `snmp_traps`.

The deploy runs both migrations automatically.

**Traps service.** `docker compose up -d` starts the `traps` service. To receive traps from the network, set `TRAP_BIND_IP=0.0.0.0` (or the management address) in the server's `.env` and run `docker compose up -d traps`. Also allow UDP 162 from the device subnets through any host firewall.

**Settings:**
- `SWITCH_MAX_CONCURRENT_POLLS`
- `SWITCH_POLL_TIMEOUT_SECONDS`
- `SWITCH_WLC_POLL_TIMEOUT_SECONDS`
- `SWITCH_WIRELESS_GROUP_TIMEOUT_SECONDS`
- `SWITCH_ALLOW_SNMPV2C`
- `TRAP_PORT` (in the container, default 1162)

**Adding a device of a new vendor:**
1. Add an `EnterpriseRule`, `OidRule` and/or `DescrRule` in `fingerprints.py`.
2. Write an adapter class and register it in `adapters.py`.
3. Add its metrics to `registry.py` with the vendor key.
4. Add a labelled fixture test.

## 13. Tests

`backend/tests/test_snmp.py`, together with the existing `test_switches.py` and `test_nms.py`, covers:
- SNMPv2c and SNMPv3 against a real local agent: GET, GETBULK walks, auth / priv, timeouts and retries
- fingerprint order, confidence and overrides
- FortiGate, FortiSwitch, Juniper EX and SRX normalisation
- the vendor alarm alert and its auto-resolve
- backoff and outage samples
- custom OID counter rates and disabled metrics
- MIB parsing and rejection
- trap normalisation for v1, v2c and v3
- the trap receiver over UDP: v2c trap, v1 trap, v3 inform, wrong source, wrong community
- trap alert raise and clear pairing
- the API: RBAC, validation, OID test, versions and rollback
- site isolation
- counter wrap / reset / reboot (test_switches)

All device data in these tests are **labelled synthetic fixtures** built from the public MIB definitions. They are not captures from devices and are not shown anywhere as monitoring data.

## 14. Not implemented (and why)

| Area | Item | What it needs |
|---|---|---|
| Cisco 9800 | RESTCONF / model-driven telemetry | SNMP covers what the Wireless module shows; RESTCONF needs a separate read-only API credential |
| Ruckus SmartZone / Ruckus One | AP, radio and client inventory | the SmartZone public REST API (separate credential and client) |
| Ruckus standalone / Unleashed APs | radio and client metrics | the Ruckus AP / Unleashed MIBs mapped and checked against a device |
| Juniper | Virtual Chassis, SRX IPsec tunnel state, BGP4-V2 (IPv6 peers), NETCONF | mapping (SNMP) or a separate optional NETCONF adapter |
| Fortinet | FortiSwitch telemetry through the managing FortiGate | poll the FortiSwitch directly for now |
| Standard | ENTITY-STATE-MIB | mapping |
| SNMP | v1 polling | not offered (traps from v1 agents are accepted) |
| Access | site scope on topology, analytics and wireless pages | extending the filter to those APIs |

Fortinet and Juniper objects are implemented from the public MIBs and tested against labelled fixtures. They show as *implemented*, not *observed*, until a real device of that line answers. The support matrix tracks this per product line.
