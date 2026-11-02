# Switch monitoring (Cisco and Ruckus ICX)

Read-only SNMP monitoring of Cisco and Ruckus ICX switches inside Sentinel Grid: inventory, health, interfaces and
traffic, errors, VLANs, MAC table, STP, LACP, PoE, environment, stacks, layer 3, events, alerts and per-metric coverage.
It reuses the SIEM's existing pieces: PostgreSQL for inventory and state, ClickHouse for time series, the worker for
polling, the alert engine (de-duplication, notifications, incidents), RBAC, the outbound guard and the Fernet secret
store. **Nothing in this module writes to a switch**: it sends only SNMP GET / GETNEXT / GETBULK.

## Architecture

| Stage | Where | Notes |
|---|---|---|
| SNMP client | `backend/app/switches/snmp.py` | pysnmp (asyncio). v3 USM (MD5/SHA/SHA-2, DES/3DES/AES-128/192/256) and v2c. Errors classified as timeout / auth / protocol / config; one request in flight per switch; one pysnmp engine per credential set |
| Identification and collection | `backend/app/switches/collect.py` | `identify()` from sysObjectID / sysDescr; standard-MIB collectors; `CiscoAdapter` and `RuckusAdapter` for enterprise MIBs. A vendor's OIDs are only ever requested from that vendor's switches |
| Capability registry | `backend/app/switches/registry.py` | every metric with group, MIB, OID, type, unit and vendors; per-device status and coverage |
| Rates | `backend/app/switches/rates.py` | counter deltas, wrap and reset handling, utilisation and sample flags |
| Poller | `backend/app/switches/poller.py` | claim (DB lease) → identify → due groups → normalise → rates → store → events → capabilities |
| Alerts | `backend/app/switches/alerts.py` | 24 rules registered in the existing alert engine, with auto-resolve and recovery notifications |
| Read side | `backend/app/switches/service.py` | overview, inventory rows, histories (raw ≤ 48 h, hourly rollups beyond) |
| Discovery | `backend/app/switches/discovery.py` | sweeps of authorised networks only |
| API | `backend/app/api/switches.py` | `/api/switches/*` |
| UI | `frontend/src/pages/switches/` | sidebar → **Switch Monitoring**: Overview, Inventory, Interfaces, Events, Settings, and a device page per switch |
| Topology | `backend/app/switches/topology.py` | LLDP / CDP graph, link health, path check |
| Storage | Alembic `0015_switch_monitoring.py`, `0016_switch_neighbors.py`, ClickHouse migration 9 | see *Storage and retention* |

Pipeline per poll: (1) connect and identify, (2) collect the groups that are due, (3) parse and normalise, (4) compute
counters and rates, (5) store time series and state, (6) the alert engine evaluates on its own cycle, (7) API / UI
read. Every group runs in isolation: a group that fails or times out is recorded and the other groups still run;
after two timeouts in one poll the remaining groups are skipped (the switch is struggling). A failing switch never
blocks the others.

## Supported vendors and models

The module identifies Cisco (enterprise 9, or "Cisco" in sysDescr) and Ruckus / Brocade / Foundry ICX (enterprise 1991,
or "ICXnnnn" in sysDescr). Anything else is monitored as **generic** with the standard MIBs only.

| Family | Identification | Notes |
|---|---|---|
| Cisco Catalyst 9200 / 9300 / 9400 / 9500 (IOS-XE 16.x / 17.x) | model from ENTITY-MIB chassis entries, version from sysDescr | StackWise, per-VLAN contexts for MAC / PVST |
| Older Catalyst (2960-X, 3650, 3850 on IOS / IOS-XE) | same | same MIBs where the release implements them |
| Ruckus ICX 7150 / 7250 / 7450 / 7550 / 7650 / 7850 (FastIron 08.0.x, 09.0.x, 10.0.x) | model and version from sysDescr, firmware from snAgImgVer | stacking, PoE controller tables |

No model or firmware is assumed to implement every MIB. The coverage page of each switch shows what it actually
returned. **Validation status:** all OIDs come from the public MIB definitions (IETF, Cisco, Foundry / Ruckus). They are
exercised by the automated tests against simulated agents built from those definitions. They have **not** yet been
validated against a production Cisco or Ruckus switch from this deployment: no switch was registered when the module
was built. Check each new model's capability page after onboarding.

## Metrics, MIBs and normalised names

Normalised names are shared by both vendors: `switch_up`, `switch_uptime_seconds`, `switch_cpu_utilization_percent`,
`switch_memory_utilization_percent`, `switch_memory_used_bytes`, `switch_temperature_celsius`, `switch_fan_ok`,
`switch_psu_ok`, `switch_poe_budget_watts`, `switch_poe_power_watts`, `switch_interfaces_up`,
`switch_interfaces_with_errors`, `switch_vlan_count`, `switch_mac_table_entries`, `switch_stp_topology_changes_total`,
`switch_route_count`, `switch_poll_duration_seconds`, `switch_metric_coverage_percent`. Per interface:
`rx_bps / tx_bps`, `rx_util / tx_util` (%), `rx_pps / tx_pps`, and per-interval increments of `in_errors`,
`out_errors`, `in_discards`, `out_discards` and `crc`.

| Group (default interval) | Standard MIBs (both vendors) | Cisco | Ruckus ICX |
|---|---|---|---|
| system (poll interval, 60 s) | SNMPv2-MIB sysDescr, sysObjectID, sysUpTime, sysName, sysLocation | — | — |
| interfaces (60 s) | IF-MIB ifTable + ifXTable (64-bit HC counters, ifHighSpeed, ifAlias, ifCounterDiscontinuityTime), EtherLike-MIB dot3StatsDuplexStatus / FCSErrors | OLD-CISCO-INTERFACES-MIB locIfInCRC, locIfResets, locIfCarrierTransitions | — |
| cpu_memory (60 s) | — | CISCO-PROCESS-MIB cpmCPUTotal (5 s / 1 min / 5 min, cpmCPUMemoryHCUsed/Free); fallback CISCO-ENHANCED-MEMPOOL-MIB, CISCO-MEMORY-POOL-MIB "Processor" | FOUNDRY-SN-AGENT-MIB snAgentCpuUtilPercent (1-min row) / snAgGblCpuUtil1MinAvg, snAgGblDynMemUtil/Total/Free |
| environment (300 s) | — | CISCO-ENVMON-MIB temperature / fan / supply tables; fallback CISCO-ENTITY-SENSOR-MIB (celsius sensors) | snAgentTemp2Table / snAgentTempTable / snChasActualTemperature (0.5 °C units), snChasFan(2)Table, snChasPwrSupply(2)Table |
| stack (300 s) | — | CISCO-STACKWISE-MIB cswSwitchInfoTable, cswRingRedundant, cswStackPortInfoTable | FOUNDRY-SN-STACKING-MIB snStackingOperUnitTable (role, state, stack-port states, image) |
| poe (300 s) | POWER-ETHERNET-MIB pethMainPseTable, pethPsePortTable | CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortPwrConsumption / Allocated (mW) | snAgentPoeGbl*, snAgentPoeUnitTable, snAgentPoePortTable (mW, keyed by ifIndex) |
| lacp (300 s) | IEEE8023-LAG-MIB dot3adAggPortTable (selected / attached aggregator, actor / partner LACP state bits) | CISCO-PAGP-MIB pagpGroupIfIndex (static / PAgP channels) | — |
| stp (300 s) | BRIDGE-MIB dot1dStp scalars and port table, RSTP-MIB dot1dStpVersion | CISCO-STP-EXTENSIONS-MIB stpxSpanningTreeType; PVST+ instances read per VLAN | — |
| vlans (900 s) | Q-BRIDGE-MIB dot1qVlanStatic / Current tables, dot1qPvid (Ruckus / generic) | CISCO-VTP-MIB vtpVlanTable, vlanTrunkPortTable; CISCO-VLAN-MEMBERSHIP-MIB vmVlan | (standard) |
| mac_table (900 s) | Q-BRIDGE-MIB dot1qTpFdbTable (BRIDGE-MIB dot1dTpFdbTable fallback) | BRIDGE-MIB per VLAN context | (standard) |
| neighbors (300 s) | LLDP-MIB (IEEE 802.1AB) lldpRemTable, lldpRemManAddrTable, lldpLocPortTable | CISCO-CDP-MIB cdpCacheTable (merged with LLDP for the same neighbor) | (standard) |
| routing (300 s) | IP-MIB ipAddrTable, IP-FORWARD-MIB inetCidrRouteNumber / ipCidrRouteNumber, OSPF-MIB ospfNbrTable, BGP4-MIB bgpPeerTable | — | — |
| inventory (3600 s) | ENTITY-MIB entPhysicalTable | — | snAgImgVer, snChasSerNum, snChasUnitSerNum |

Derived values and their limits:

* **STP port roles** are derived (root port from dot1dStpRootPort, designated when the port's designated bridge is
  this switch, alternate / backup when blocking). BRIDGE-MIB has no role column.
* **Ruckus stack topology** (ring / chain) is derived from the stack-port states.
* **Cisco PoE ports** (RFC 3621 index group.port) are mapped to interfaces by name (`Gi1/0/12` ↔ `1.12`, front-panel
  module 0 first). Ambiguous ports stay unmapped and are counted as "unmapped" on the PoE tab.
* **SVIs**: Cisco `VlanN` interfaces are mapped to VLAN N by name. Ruckus `ve` numbers need not equal the VLAN id, so
  they are listed only as interfaces.

## Topology (LLDP / CDP)

**Switch Monitoring → Topology** draws the layer-2 graph from the neighbor tables of the monitored switches, and each
switch has a **Neighbors** tab.

* LLDP local port numbers are mapped to interfaces through lldpLocPortTable (port id = interface name or MAC); they are
  not assumed to be ifIndexes. Port names are normalised (`TenGigabitEthernet1/1/1` = `Te1/1/1`).
* A neighbor is matched to a monitored switch by management IP, then system name (domain stripped), then chassis /
  interface / stack MAC; and to a registered firewall by IP or name. Anything else is an external node typed from its
  advertised capabilities (switch, router, AP, phone, host, firewall from the system description). APs, phones and
  hosts are hidden unless *show APs, phones and hosts* is ticked.
* A cable seen from both ends is merged into one link ("both ends"); parallel links (LAG members) are drawn as one edge
  with a count.
* Link status: **up**; **degraded** (≥ 80 % utilisation or errors in the last poll on either end); **down** (either
  end's interface not up); **lost** (the neighbor disappeared within the look-back window, default 24 h, drawn dashed);
  **unknown** (local port not mapped).
* **Connectivity check**: shortest path between any two devices over links that are up or degraded. When there is
  none, it shows the topology path and the links on it that are down or lost.
* Events: neighbor_added, neighbor_removed, neighbor_changed (remote port changed). Alert **switch_topology_link_lost**
  fires when a neighbor that is a monitored switch, a firewall, a router or a bridge disappears (high when the local
  port is also down), and resolves when the neighbor is seen again.
* Requirements: LLDP enabled on the switches (Cisco `lldp run`, Ruckus `lldp run`), or CDP on Cisco. Devices that
  expose only the LLDP-V2-MIB (1.3.111.2.802.1.1.13) are not read yet.

## Metric coverage and capability detection

Every metric in the registry gets a status per switch, worked out from what the switch returned:

| Status | Meaning |
|---|---|
| healthy | collected on the last attempt and fresh |
| unavailable | collected before, missing on the last attempt (a sensor or PSU was removed, a table emptied) |
| unsupported | the switch has never returned it (noSuchObject / empty table) |
| failed | the last attempt raised an error (timeout, authorisation, protocol) |
| stale | the last success is older than 3 × the group's interval |
| not_configured | the group is disabled for this switch, or it needs device configuration (for example SNMPv3 VLAN contexts) |

**Coverage** = healthy ÷ (healthy + unavailable + failed + stale). Unsupported and not-configured metrics are counted
separately, so a switch without PoE is not "less covered" for lacking PoE. A missing measurement is `null` / "—" all
the way to the UI; it is never stored or shown as 0. The device's **Monitoring health** tab lists every metric with its
source MIB, OID, status, last success and last error, along with per-group timing and the history of the last 200
polls.

## Counters, rates and false-spike protection

Rates are always (current − previous) ÷ elapsed seconds between two valid samples. 64-bit HC counters are used when the
interface has them; otherwise the 32-bit IF-MIB counters. No rate is produced (the sample is flagged `counter_reset`)
when:

* sysUpTime decreased (a restart),
* ifCounterDiscontinuityTime changed,
* the ifIndex now names a different interface (renumbering after a reload or module change),
* a 64-bit counter decreased,
* a 32-bit counter decreased and the wrap-corrected delta would exceed the link speed (a reset, not a wrap),
* the rate exceeds 1.5 × the interface speed.

Other flags: `gap` (the sample spans more than 3 × the interval; the average over the gap is kept but alerts ignore
it), `uncertain_utilization` (a virtual interface, a 32-bit counter that can wrap more than once in the interval, or a
rate above the link speed), `32bit_counters`, `speed_unknown`. Speed is ifHighSpeed (Mbit/s); ifSpeed is only used
below its 4,294,967,295 saturation point. SVIs, loopbacks and tunnels get no utilisation.

## Storage and retention

| Data | Store | Retention |
|---|---|---|
| switches, credentials (encrypted), networks, interfaces (latest state and last raw counters), VLANs, MAC table, poll history, discovery runs | PostgreSQL | MAC entries absent for 30 days are removed; poll history 14 days; events `SWITCH_EVENT_RETENTION_DAYS` (180) |
| `switch_metrics` (device gauges; label `component` = CPU / sensor / PSU / fan / PoE unit name) | ClickHouse | 90 days |
| `switch_metrics_hourly` (min / max / sum / samples) | ClickHouse, materialised view | 400 days |
| `switch_if_samples` (per interface per poll: rates, increments, oper / admin, flags) | ClickHouse | 35 days |
| `switch_if_hourly` (avg / peak rates, peak utilisation, summed errors, down samples) | ClickHouse, materialised view | 400 days |

High-cardinality data (MAC addresses, descriptions, configuration text) is never used as a time-series label; it lives
in PostgreSQL. Charts read raw samples for ranges up to 48 h and the hourly rollups beyond. Sizing: one switch with 52
interfaces polled every 60 s writes about 75,000 interface rows a day, roughly 1–2 MB compressed in ClickHouse.

## Polling, limits and scheduling

* Due switches are claimed with a database lease, so two worker replicas never poll the same switch, and no switch has
  two polls in flight. Global concurrency: `SWITCH_MAX_CONCURRENT_POLLS` (16). Per switch: one SNMP request at a time,
  GETBULK with 25 repetitions, several table columns walked side by side, at most 20,000 rows per walk.
* Per switch: poll interval (default 60 s), SNMP timeout (3 s), retries (1), per-group intervals (`0` disables a group,
  which marks its metrics `not_configured`) and alert threshold overrides. Whole-poll timeout:
  `SWITCH_POLL_TIMEOUT_SECONDS` (240 s).
* Reachability is damped: **down** after 2 consecutive failed polls. Rejected SNMPv3 credentials put the switch into
  **auth_failed** immediately, because an unreachable switch and a credential problem need different fixes.
* Cisco per-VLAN reads (MAC table, PVST+) cover at most `SWITCH_MAX_VLAN_CONTEXTS` (64) VLANs and `SWITCH_MAX_MACS`
  (50,000) entries per poll.

## Alerts

Alert rules (Detections / Alerts → rules; thresholds are rule parameters, which a switch's `thresholds` can
override): switch_unreachable, switch_snmp_auth, switch_stale_metrics, switch_cpu_high, switch_memory_high,
switch_temperature_high, switch_psu_failure, switch_fan_failure, switch_poe_budget, switch_port_down,
switch_port_up_unexpected, switch_if_utilization, switch_if_errors, switch_if_discards, switch_if_flapping,
switch_stp_topology, switch_stp_root_change, switch_lacp_member, switch_stack_member, switch_mac_move, switch_restart,
switch_firmware_change, switch_routing_neighbor, switch_topology_link_lost.

Each alert carries the switch, management IP, site, component, metric, observed value, threshold, detection time,
last healthy time (where known), a link to the switch and suggested troubleshooting steps. The engine's group key
de-duplicates alerts: a later poll updates the open alert, so the same condition is never re-notified every cycle.
State-type rules (unreachable, auth, stale, CPU, memory, temperature, PSU, fan, PoE, port down, utilisation, LACP,
stack, routing neighbour) **resolve themselves** when the condition clears and emit `alert.resolved`, which
notification rules (Slack / Teams / email / webhook) can subscribe to. Rate rules ignore samples flagged gap, reset or
uncertain, and every rule requires a recent successful poll. Down-port alerts cover uplinks only (trunks, LAG members,
port-channels, or descriptions matching `watch_regex`), and only for ports seen up while monitored. A single MAC move
is an event, not an alert; the alert needs repeated moves of one MAC, many moves at once, or a learning burst, and it
lists the ports as evidence.

**Correlation with the firewalls:** switch alerts carry the IDs of the firewalls registered at the same site, so
incident correlation groups a switch outage with that site's FortiGate ISP / VPN / reachability alerts. Without a
firewall at the site, switch alerts correlate per site. The device page also lists the open firewall alerts at the
same site.

## Onboarding

1. **Settings → Authorised management networks**: add the switch management subnets (CIDR, at most /16). Switches can
   only be added, polled and discovered inside these networks. Addresses must be IP literals (no DNS, nothing to
   rebind); loopback, link-local and reserved ranges are refused.
2. **Settings → SNMP credential profiles**: create an SNMPv3 authPriv profile (SHA-256 + AES-128 or stronger where
   supported). Passphrases are Fernet-encrypted with `TOKEN_ENCRYPTION_KEY` and never returned by the API. SNMPv2c is
   refused unless `SWITCH_ALLOW_SNMPV2C=true` is set for switches where it is explicitly approved.
3. **+ Add switch** → **Test connection & detect metrics**: tests reachability and credentials, identifies the vendor
   and model, lists every metric with supported / unsupported status, and previews the values. Nothing is stored. Then
   **Add and start monitoring**.
4. Bulk: **Settings → Bulk import (CSV)** with columns `name,address,credential[,site,building,floor,rack,role,port,poll_interval_seconds,notes]`.
   Validate first; the import is all-or-nothing.
5. Discovery: enable *allow discovery* on an authorised network and start a run. It sends a single GET per address
   (1 s timeout, no retries, bounded concurrency, at most `SWITCH_DISCOVERY_MAX_HOSTS` addresses) and adds nothing
   automatically.

Per switch: **Poll now**, **Test**, **Pause / Resume**, **Edit**, **Remove**, and polling errors and collection
history on the Monitoring health tab.

### Switch-side configuration (read-only)

Cisco IOS-XE (adapt names; `SIEM-ACL` admits only the SIEM's address):

```
ip access-list standard SIEM-ACL
 permit <siem-address>
snmp-server view SIEM-RO iso included
snmp-server group SIEM v3 priv read SIEM-RO access SIEM-ACL
snmp-server group SIEM v3 priv context vlan- match prefix read SIEM-RO access SIEM-ACL
snmp-server user siem-ro SIEM v3 auth sha <auth-passphrase> priv aes 128 <priv-passphrase>
```

Without the `context vlan-` line, the MAC table and per-VLAN STP show as **not_configured**, and the reason says so.

Ruckus ICX (FastIron; check the exact syntax in the Security Configuration Guide for your release):

```
snmp-server group SIEM v3 priv read all
snmp-server user siem-ro SIEM v3 auth sha <auth-passphrase> priv aes <priv-passphrase>
```

Use an ACL that admits only the SIEM's address, and never a read-write community or group.

## Security

* Read-only by construction: the client has no SET call; there is no configuration change path in the module.
* Backend RBAC: analysts read; administrators onboard, edit, poll, test, discover and manage credentials and networks.
* Credentials are encrypted at rest, write-only through the API, and never placed in logs, URLs, metric labels or
  error messages. SNMP error texts are checked in the tests for leaked keys.
* SSRF and scanning protection: IP-literal management addresses, the outbound guard (no loopback / link-local /
  metadata / reserved), authorised networks for polling and discovery, subnet-size cap, and rate limits on test (10/min),
  poll-now (10/min), import (10/min) and discovery (3/min).
* Timeouts, retries, per-switch serialisation and global concurrency bound the load on switches.
* Every onboarding and configuration change is written to the audit log.

## Testing

```
cd backend && ../.venv/bin/python -m pytest -q tests/test_switches.py   # switch module (simulated agents, no network devices)
cd backend && ../.venv/bin/python -m pytest -q                          # whole backend (regression)
cd frontend && npx tsc --noEmit && npx vitest run
```

`tests/switch_fixtures.py` holds sanitised, synthetic responses for a Cisco C9300 stack and a Ruckus ICX 7150 stack;
`tests/snmp_sim.py` holds an in-memory client and a **real SNMP agent on 127.0.0.1** (pysnmp command responder) used to
test GET / GETBULK, SNMPv3 authPriv, wrong keys and timeouts over the wire.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Test: "no SNMP response" (timeout) | UDP 161 blocked, the switch's SNMP ACL does not include the SIEM, or (v2c) a wrong community: agents drop wrong communities silently |
| Test / state: auth_failed | wrong SNMPv3 user, protocol or passphrase; the switch's engine ID changed after a replacement or re-image |
| A metric shows **unsupported** | the switch's software does not implement that MIB object; check the release's MIB support list |
| MAC table / per-VLAN STP **not_configured** on Cisco | add `context vlan- match prefix` to the SNMPv3 group (v2c uses community@vlan indexing automatically) |
| Utilisation "—" | no reliable interface speed, a virtual interface, or no valid sample yet (first poll, counter reset) |
| Polls slow / groups skipped | raise the SNMP timeout for that switch, lengthen group intervals, or disable unneeded groups |
| Metrics **stale** | the worker is not running or the switch keeps failing; see Monitoring health → collection history |

## Known limitations

* OIDs have not yet been validated against the production switches (none were registered when the module was built).
  Review each new model's capability page.
* Duplex comes only from EtherLike-MIB; switches without it show "—". Queue drops are not collected (they are
  vendor and QoS-policy specific).
* Ruckus VE-to-VLAN mapping, MSTP instance detail, and per-member LACP partner details beyond the state bits are not
  collected.
* "Interface resets" and "carrier transitions" are Cisco-only (OLD-CISCO-INTERFACES-MIB).
* Topology is layer 2 as seen by LLDP / CDP: links to devices that run neither (or have it disabled per port) are
  missing from the graph; LLDP-V2-MIB-only devices are not read.
* No SNMP traps or syslog parsing from switches yet; state changes between polls are detected from ifLastChange,
  counters and table differences.
* REST / NETCONF / CLI collection is not implemented; everything is SNMP.
