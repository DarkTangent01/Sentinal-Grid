# Generic SNMP device monitoring and interface bandwidth history

Sentinel NMS monitors **any SNMP device**, not only switches. Supported kinds:
- network gear: switches, layer 3 switches, routers, firewalls, wireless controllers, access points, load balancers, network appliances;
- hosts: servers, Linux and Windows servers, storage systems, hypervisors;
- facilities: printers, UPS and IoT / building devices;
- generic SNMP devices.

It keeps persistent, queryable interface bandwidth history for all of them.

This document covers what exists, what was added, how it fits together, and the limits.

## 1. Architecture audit (before this change)

| Area | What existed | Decision |
|---|---|---|
| Inventory | PostgreSQL `switches` table and `/api/switches`, with SNMP credential profiles (`switch_credentials`, sealed at rest), authorised management networks, CSV import and discovery runs | **Reused** as the inventory for every device. It isn't renamed: a renamed table would break data, foreign keys and links. The UI calls them devices. |
| SNMP | `switches/snmp.py`: read-only pysnmp asyncio client for v2c and v3 (all USM auth / priv protocols), GETBULK multi-column walks, error classes (timeout / auth / protocol) | **Extended** with SNMPv1 |
| Identification | `switches/fingerprints.py`: sysObjectID → sysDescr rules for Cisco, Fortinet, Juniper and Ruckus; unknown → generic | **Extended** with a manufacturer table and device categories |
| Polling | `switches/poller.py`: database lease per device (no double polls across workers), bounded global concurrency, per-group intervals, isolated groups, damped reachability, auth-failure state | **Reused** |
| Counters | `switches/rates.py`: deltas over the real elapsed time; restart / discontinuity / ifIndex renumbering / 64-bit reset / implausible-rate refusal; 32-bit wrap correction; GAP / RESET / UNCERTAIN_UTIL flags | **Reused** (already met the counter requirements) |
| Interfaces | IF-MIB and IF-MIB ifXTable: HC octets and unicast / multicast / broadcast packets, errors, discards, speed (ifHighSpeed), admin / oper state, alias, MAC, MTU; LAG / port-channel membership (IEEE8023-LAG); kinds physical / lag / svi / virtual | **Reused** |
| Time series | ClickHouse `switch_if_samples` (every poll, 35 days) and `switch_if_hourly` (400 days); `switch_metrics` / hourly for device health | **Extended** with a 5-minute rollup and configurable retention |
| Health | CPU / memory (vendor, HOST-RESOURCES, UCD-SNMP), ENTITY-SENSOR temperatures / fans / PSUs, storage, PoE, stack; unsupported = "missing", never 0 | **Extended** with UPS-MIB and Printer-MIB |
| Alerts | Rule registry in the shared alert engine: dedup by group key, auto-resolve with recovery notifications, utilisation / errors / discards / flapping / port down | **Extended**: three utilisation levels, per-interface thresholds and monitoring flag, a capacity-mismatch rule |
| Observability | Poller self-metrics (loop lag, polls, durations), Prometheus `/api/metrics`, Polling Health page | **Reused** |
| Gaps found | Switch-only wording and device types; no SNMPv1; no templates; no UPS / printer health; graphs had only fixed ranges, no statistics (95th percentile, totals) and no comparison; no global interface quick filters, export or column choice; no per-interface thresholds | **Built** (sections 2–9) |

## 2. Device inventory and classification

- **Device types** (`fingerprints.DEVICE_TYPES`):

  | Key | Kind |
  |---|---|
  | `switch` | switch |
  | `l3switch` | layer 3 switch |
  | `router` | router |
  | `firewall` | firewall |
  | `wlc` | wireless controller |
  | `ap` | access point |
  | `server` | server |
  | `linux` | Linux server |
  | `windows` | Windows server |
  | `printer` | printer |
  | `ups` | UPS |
  | `load_balancer` | load balancer |
  | `storage` | storage system |
  | `hypervisor` | hypervisor |
  | `appliance` | network appliance |
  | `iot` | IoT / building device |
  | `other` | generic SNMP device |

- **Detection order:**
  1. sysObjectID product subtree;
  2. enterprise number → manufacturer (about 60 enterprises: Microsoft, VMware, APC, Eaton, HP, Aruba, Dell, printer makers, NetApp, Synology, F5, Citrix, Palo Alto, Check Point, MikroTik, Arista and others);
  3. sysDescr category rules (ESXi, Windows, Jetdirect / LaserJet, UPS cards, RouterOS, BIG-IP, ONTAP, Linux and so on);
  4. otherwise "generic SNMP device".

  Vendor **adapters** still exist only for Cisco, Fortinet, Juniper and Ruckus. Every other device gets standard-MIB monitoring.
- **Manual classification:** `device_type_override` always wins over detection, and the poller keeps it.
- **New device fields** (migration 0041): FQDN, tags, ICMP on / off, monitoring template. Site, building, floor, rack, role and description already existed.

## 3. Add Device workflow

`POST /api/devices/onboard` (administrators; rate-limited). It never saves a device whose SNMP test failed.

1. **Validate.** The address must be an IP literal inside an authorised management network, not loopback / link-local / reserved. An FQDN is resolved when no IP is given, and the result is validated the same way.
2. **Check for duplicates** by name and management address.
3. **Check the SNMP profile.** The version must be allowed: v1 and v2c only when `SWITCH_ALLOW_SNMPV2C=true`.
4. **Ping** (optional; reported as "not tested" when the server cannot send ICMP).
5. **Run the SNMP probe:** sysDescr, sysObjectID, sysName, sysUpTime, sysLocation, sysContact, identification (vendor, model, OS, firmware, type), capabilities, interfaces (names, descriptions, types, speeds, states), CPU / memory / environment / storage / LAG, UPS and printer MIBs.
6. **Save** with the chosen template (or the one for the detected type), and start polling.

The response lists every step with ok / failed / skipped and one outcome:

| Outcome | Meaning |
|---|---|
| `added` | Saved and monitoring |
| `partial` | Saved, but no interfaces were discovered |
| `inventory_only` | SNMP monitoring was switched off by the administrator |
| `auth_failed` | The device rejected the SNMPv3 user or its keys |
| `unreachable` | No ping reply and no SNMP answer |
| `snmp_no_response` | Answers ping but not SNMP (disabled, filtered, ACL, or a wrong v1 / v2c community) |
| `unsupported_response` | An SNMP answer Sentinel could not use |
| `duplicate` | Another device already uses this name or address |
| `invalid` | The configuration or address was rejected |

**Secrets:** SNMP communities and SNMPv3 passphrases exist only in credential profiles, sealed with the platform token cipher. They are never returned (tests assert this).

**Discovery** (unchanged): it runs only inside networks marked `allow_discovery`, with SNMP / ICMP / TCP / ARP methods, bounded concurrency, short timeouts and a hard subnet cap. Results are candidates an administrator adds; nothing is onboarded automatically.

## 4. SNMP versions

| Version | Authentication | Walks | Notes |
|---|---|---|---|
| v3 | noAuthNoPriv, authNoPriv, authPriv; MD5 / SHA-1 / SHA-224…512; DES / 3DES / AES-128…256 | GETBULK | Recommended |
| v2c | community | GETBULK | Off unless approved (clear text) |
| v1 | community | GETNEXT, one column at a time | Off unless approved. **v1 cannot carry Counter64**: interfaces fall back to 32-bit counters, with wrap correction and refusal of implausible deltas. |

## 5. Bandwidth calculation

`rates.interface_rates` computes the rates:

- **bits per second** = Δoctets × 8 / *actual* elapsed seconds between the two samples;
- **utilisation** = bps / speed × 100. Speed comes from ifHighSpeed, else ifSpeed. Utilisation is not calculated when the speed is unknown or zero (flag UNCERTAIN_UTIL).

A delta is refused when:
- the device restarted (sysUpTime went back);
- the counter discontinuity time changed;
- the ifIndex now names another interface;
- a 64-bit counter went down;
- a 32-bit wrap would exceed the line rate;
- the rate exceeds 1.5 × speed.

A sample across a polling gap is flagged GAP. The next valid pair starts a new baseline, so a negative or spiking value is never produced.

## 6. History storage (ClickHouse, UTC)

| Table | Resolution | Default retention | Used for |
|---|---|---|---|
| `switch_if_samples` | every poll (60 s) | 35 days | ranges up to 2 days; exact totals |
| `switch_if_5m` (new, migration v23) | 5 minutes: avg / min / max, bits transferred, errors, discards, down samples | 90 days | 2–90 day ranges; 95th percentile |
| `switch_if_hourly` | 1 hour | 400 days | longer ranges |

- **Rollup:** the 5-minute rollup is fed by a materialised view from raw samples (RESET samples excluded). It was back-filled day by day from existing samples, so there is no 60-second statement and no double count on a retried migration.
- **Retention** is editable under Devices → Templates → Interface history retention, or `PUT /api/devices/retention`. It is validated (raw ≤ 5-minute ≤ hourly, with limits) and applied with `ALTER TABLE … MODIFY TTL`.
- **Persistence:** history lives in ClickHouse and the counter baselines in PostgreSQL (`switch_interfaces.counters`), so restarts of the API, poller, worker or containers lose nothing. The first poll after a restart resumes from the stored baseline; a gap is flagged, not filled.

## 7. Interface views

- **Device → Interfaces tab:** a searchable, filterable table. A row opens the interface page.
- **Interface page** (`/switches/{id}/interfaces/{ifIndex}`):
  - **Overview:** description, type, speed with its source, duplex, MTU, MAC, VLANs, LAG, last change, 64- / 32-bit counters.
  - **Bandwidth chart:** inbound and outbound, with a choice of units (auto, Kbps, Mbps, Gbps, MB/s, GB/s).
  - **Time ranges:** 15 minutes, 1 hour, 6 hours, 24 hours, 7 / 30 / 90 days, 1 year, or custom start–end.
  - **Comparison:** previous period, same time yesterday, or same time last week, drawn dashed on the same axis.
  - **Statistics:** current, average, peak, minimum, 95th percentile, data transferred and peak utilisation per direction, plus errors, discards and valid-sample coverage.
  - **Charts:** utilisation, and errors and discards.
  - **Alert thresholds** and the alert on / off switch.
  - **Alerts and state-change events.**
  - **Stale indicator:** shown when the device has not been polled successfully for three intervals.
  - **No data:** "No historical data available yet."
- **Global Interfaces** (`/nms/interfaces`):
  - **Quick filters:** down, high utilisation, errors, discards, no data, changed in 24 hours, alerts off.
  - **Search and filters:** by layer (physical only / logical only, so aggregate and member traffic are never added together), device type and site.
  - **Table tools:** sortable columns, paging, column choice (kept per browser), bulk alerts on / off, CSV export.
  - **API:** `/api/devices/interfaces` adds device, vendor, minimum utilisation, minimum speed, VLAN and LAG filters.

**Accuracy rules:**
- Every value comes from stored samples.
- Buckets with no valid sample are absent; the line breaks, and nothing is interpolated.
- Statistics count only rated samples and say which table and resolution they came from.
- Totals are exact from raw and 5-minute data, and marked "estimated" from hourly data.

## 8. Alerts

| Rule | What it does |
|---|---|
| `switch_if_utilization` | **Three levels:** warning 70% (low), high 85% (medium), critical 95% (high). Needs 3 consecutive valid samples (GAP / RESET / UNCERTAIN_UTIL ignored). There is one alert per interface and direction; its severity follows the level, and it auto-resolves with a recovery notification. **Threshold order:** interface → device → template → rule parameters. A device's older `util_pct` setting is honoured as the "high" level. |
| `switch_if_capacity_mismatch` (new) | A physical link that is up negotiated at least 2× below the highest speed it has run at, e.g. 100 Mbit/s on a gigabit port. |
| Existing | Errors, discards, flapping, port down, unexpected port up, LACP member, device unreachable, SNMP auth failure, stale metrics, CPU / memory / storage / temperature, PSU / fan and others. These are unchanged and keep their dedup, cooldown and recovery behaviour. |

Interfaces with alerts switched off, or excluded by a template rule (ifType or name pattern), still store traffic but raise no utilisation alerts.

## 9. Monitoring templates

- **Built-in templates:** Generic SNMP Device, Generic Network Switch, Router, Firewall, Wireless Controller, Access Point, Linux Server, Windows Server, UPS, Printer.
- **Template contents:** device polling interval, per-group intervals (0 = off), thresholds (utilisation levels, CPU, memory, storage, temperature, errors, discards), and interface rules (excluded ifTypes, name regex).
- **Editing:**
  - Built-ins can be edited but not deleted. Administrators can add their own.
  - Applying a template copies it into the device (`template_config`), so a poll needs no extra query.
  - Editing a template refreshes every device that uses it.
  - Device-level settings still win.

## 10. Device health

Standard MIBs are used first; vendor MIBs through the adapters.

- **CPU, memory and storage:** HOST-RESOURCES, UCD-SNMP.
- **Sensors and hardware:** ENTITY-SENSOR, ENTITY.
- **UPS** (new `ups` group, UPS-MIB): battery status, charge, runtime remaining, on battery, output source, load, battery temperature, alarms, input / output voltage.
- **Printer** (new `printer` group, Printer-MIB + hrPrinterTable): status, error conditions (low / no paper or toner, jam, door open, offline, service), supply levels, page count.

These two groups run only for devices of that type, unless a template enables them. Metrics a device doesn't answer are shown as **Not supported**, never 0.

## 11. API summary (`/api/devices`, Sentinel NMS, authenticated; writes need an administrator)

| Method | Path | Purpose |
|---|---|---|
| GET | `/meta` | Device types, templates, ranges, utilisation defaults |
| POST | `/onboard` | Add a device (section 3) |
| PATCH | `/{id}` | Manual type, template, FQDN, tags, ICMP |
| GET / POST / PUT / DELETE | `/templates`, `/templates/{id}` | Monitoring templates |
| GET / PUT | `/retention` | Interface history retention |
| GET | `/interfaces`, `/interfaces/export.csv` | Global interface view and export |
| GET | `/{id}/interfaces/{ifIndex}/bandwidth?range= \| start=&end=&compare=` | Series, statistics, current value, comparison |
| PATCH | `/{id}/interfaces/{ifIndex}` | Monitored flag, per-interface thresholds |

Device CRUD, test, poll now, pause / resume, credential profiles, networks, discovery, CSV import, device / interface lists, the interface detail and the time series stay under `/api/switches` (unchanged paths). Site scoping applies everywhere: out-of-scope devices return 404.

## 12. Performance

- **Polling** is asynchronous. Concurrency is bounded globally and per device (one request in flight). A database lease means replicas never double-poll. Groups are isolated, with per-group timeouts.
- **Load on devices:** multi-column GETBULK walks (one request carries every column), and expensive groups (MAC table, VLANs) on long intervals. Templates switch off what a device type doesn't have.
- **Writes:** one ClickHouse insert per poll for all interfaces. Rollups are computed by ClickHouse; the API never scans raw samples beyond 2 days.
- **API:** list queries filter, sort and page in SQL.
- **Observability:** poller self-metrics (loop lag, poll durations, timeouts, overdue devices) on the Polling Health page and `/api/metrics`.

## 13. Limits

- SNMPv1 devices have only 32-bit counters. On links faster than about 1 Gbit/s at 60-second polling, a 32-bit counter can wrap more than once per interval: such deltas are refused (no value), not guessed.
- The interface **IP address** is not shown per interface yet (ipAddrTable is collected for routing / topology but not joined to the interface page).
- A device's LAG imbalance is visible from member rates on the interface page and the global view (physical-only filter); there is no dedicated imbalance alert.
- **Discovery** stays limited to authorised networks with discovery enabled; there is no free-form "scan any range" by design.
- **Retention changes** apply to ClickHouse TTLs immediately; data beyond a shortened period is removed at the next merge and can't be recovered.

## 14. Tests

| Area | Coverage |
|---|---|
| `backend/tests/test_devices.py` | Type detection; templates (seeding, precedence, propagation, UPS / printer group gating); onboarding outcomes (auth failure, no response, unreachable, outside networks, added, partial, duplicate, no secrets in responses, RBAC); bandwidth series, statistics, exact totals, 95th percentile, reset exclusion, 5-minute rollup agreement, empty data → no numbers; retention validation and TTL application; three-level utilisation with interface thresholds and alerts off; capacity mismatch; global quick filters, PATCH, export, custom-range validation; UPS / printer collectors |
| `backend/tests/test_switches.py` | Counter wrap / reset / restart / gap / 32-bit fallback; a real local SNMP agent over UDP for v1 (GETNEXT walks, no Counter64), v2c and v3 (auth / priv, wrong keys, wrong community); polling persistence; leases; alerts with recovery; API RBAC and validation |
| `frontend/src/pages/devices/bandwidth.test.ts` | Unit choice and conversion, no invented values, comparison shift |
