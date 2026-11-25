# Sentinel NMS: topology impact, anomalies, capacity, config backup, flows, rogues, self-monitoring, reports

Read-only toward network devices throughout: SNMP GET / WALK, fixed SSH show commands, and passive receivers
(flows, traps). Nothing here changes a switch or controller configuration. Enabling flow export, client traps or an
SSH backup account on a device is an administrator's action and is described per feature.

## 1. Topology, failure impact, dependency-aware alerting

| What | Where |
|---|---|
| AP nodes on their uplink switch ports (from the controller's CDP data) | Switch Monitoring → Topology (toggle "controller APs") · `GET /api/switches/topology?aps=true` |
| "If this switch fails": downstream switches, APs, clients now, SSIDs | click a switch in the topology · `GET /api/switches/{id}/impact` |
| Upstream (parent) suggestions from LLDP / CDP | Device Dependencies → "Suggested from LLDP / CDP" · `GET /api/nms/dependencies/suggestions` |
| APs behind a down switch are not alerted on their own | `wireless_ap_down` skips them; the root's `switch_unreachable` alert lists `dependent_aps` and `affected_clients` |

- **Suggestions:**
  - **Roots:** core-role switches, else switches cabled to a firewall, else the best-connected switch.
  - **Parents:** each other switch gets the neighbour one hop closer to a root, preferring the higher role.
  - **Never automatic:** a suggestion is applied only when an administrator accepts it, and a configured parent is
    never changed.
- **Impact calculation:** uses the configured parents, filling in suggested ones only for devices that have no
  configured parent.

## 2. Anomaly detection (seasonal baselines)

- **Baseline:** for each series, the median and MAD of the same time of the week over the previous weeks.
- **Learning period:** no alert until at least 3 weeks have data.
- **Gaps:** a week without readings is a gap, never a zero.
- **Rules:**

  | Rule | Series |
  |---|---|
  | `wireless_ssid_clients_anomaly` | concurrent clients per SSID (30-minute slot); drops by default, spikes optional |
  | `wireless_ap_zero_clients` | an AP that is up with no client at a time it usually serves ≥ 5 |
  | `switch_if_util_anomaly` | interface peak utilisation, hour of week, above a 60 % floor |

- **UI:**
  - "Anomalies" card on the Network Dashboard.
  - Usual-range band on the hourly client chart when one SSID is selected (`expected_weeks=4`).

## 3. Capacity forecasting additions

Added to Capacity Planning, using the same linear trend and days-to-threshold logic as interface forecasts:
- **PoE:** % of budget per switch / stack unit.
- **APs:** daily peak concurrent clients against the controller's `ap_clients_max`.
- **SSIDs:** peak against the WLAN's configured maximum client count, when it has one.

**Not forecast:** DHCP scope and IP-pool usage. No DHCP or IPAM data is collected.

## 4. Read-only configuration backup (SSH)

- **Commands:** a fixed list per vendor, nothing else, and never configuration mode:

  | Vendor | Command |
  |---|---|
  | Cisco | `show running-config` |
  | Juniper | `show configuration \| display set \| no-more` |
  | Ruckus ICX | `skip-page-display` + `show running-config` |

- **Address check:** the same as SNMP polling: an IP literal inside an authorised management network.
- **Host keys:**
  - The first connection stores the key (trust on first use).
  - A different key later stops backups before any password is sent, and raises `switch_ssh_hostkey_changed`.
  - An administrator re-trusts it with "Accept new key".
- **Secrets:** passwords, secrets, keys, SNMP communities and PSKs are masked before storage. Volatile lines
  (timestamps, byte counts) are removed.
- **Versions:** a new version is stored only when the configuration changed, with a unified diff. The alert
  `switch_config_changed` fires for it, and maintenance windows apply.
- **Schedule:**
  - every 24 h (`CONFIG_BACKUP_INTERVAL_HOURS`);
  - plus after a `ciscoConfigManEvent` trap;
  - "Back up now" queues the device for the worker (runs within 10 min).
- **Access:**
  - The configuration text and diffs are administrators only, and every view or download is audited.
  - Everyone with NMS access sees the change list.

**Your step:** create a read-only account on the devices, add it under Config Changes → SSH credentials, then assign
it to devices.

## 5. Flow collection

- **Service:** `flows` (`python -m app.flows`), decoding:
  - NetFlow v5 / v9 and IPFIX on UDP 2055 / 4739;
  - sFlow v5 on 6343.
- **Exporters:** only inventory devices (switch / controller management addresses, registered firewalls) are
  accepted. Anything else is counted and dropped.
- **Sampling:** sampled exports are scaled by their sampling rate, so totals are estimates.
- **Storage:**
  - raw records: 30 days;
  - per interface / service rollup: 400 days;
  - per talker pair rollup: 90 days.
- **UI:** NMS → Flow Analytics (top talkers, sources, destinations, applications / ports, interfaces, VLANs,
  exporters).

**Your step:**
1. Set `FLOW_BIND_IP` in `.env` (the ports stay on loopback until then).
2. Configure the devices to export to the server.

## 6. Wireless: rogue APs, floor experience, AP power, controller client notifications

- **Rogue APs:**
  - **Source:** the controller's rogue table (AIRESPACE `bsnRogueAPTable`; OIDs read from Cisco's MIB), polled every
    15 minutes in the controller's wireless job.
  - **Rule `wireless_rogue_detected`:** flags rogues that are classified malicious, broadcast one of our SSIDs, or
    are seen on the wired network.
  - **Not flagged:** rogues the controller marks known / acknowledged / friendly.
  - **UI:** Wireless → Rogue APs.
- **Floor experience:**
  - **SLA:** share of clients with a good experience score per site / building / floor, against a target
    (`wireless_floor_sla_breach`).
  - **Trend:** daily share of readings with usable RSSI and SNR.
  - **UI:** Wireless → Floor Experience.
- **AP power (`wireless_ap_poe_issue`):** an AP that is down while its switch port is not delivering PoE, or an AP
  running at low power (`cLApPowerStatus`).
- **Controller client notifications (receiver side):**
  - CISCO-LWAPP-DOT11-CLIENT-MIB traps `599.0.4 / 6 / 7 / 9 / 10 / 11`;
  - AIRESPACE station traps `14179.2.6.3.1 / 2 / 3 / 4 / 53`.

  They are stored as client-history events (`trap_assoc`, `trap_disassoc`, `trap_deauth`, `trap_auth_fail`,
  `trap_assoc_fail`; precision `controller_trap`) and appear in the client's history. They are kept apart from the
  polled sessions, so nothing is counted twice.

  **Your step:**
  1. Enable these traps on the 9800, sent to the server's trap address.
  2. Use the controller's SNMPv3 profile, as for other traps.

**Not built:** gNMI streaming telemetry. It needs gRPC dial-in configuration on the controller and a new protocol
stack.

## 7. Monitoring the monitor

- **Process figures:** every worker / poller process writes its own figures each minute to `nms_self_metrics`
  (30 days): event-loop lag, CPU, memory, polls in flight, and duration and last run of each periodic loop.
- **Objectives** (NMS → NMS Self-Monitoring):

  | Objective | Target |
  |---|---|
  | Switches with fresh metrics | ≥ 99 % |
  | Wireless controllers with fresh metrics | ≥ 99 % |
  | Worst loop lag p95 | ≤ 0.5 s |
  | Alert pass | ≤ 300 s |
  | Client rollup age | ≤ 15 min |
  | Processes reporting | ≥ 1 |

- **Alert:** a missed objective raises `nms_self_slo_breach`.
- **Prometheus:** `/api/metrics` (administrators) adds `nms_slo_value`, `nms_slo_ok` and
  `nms_process_metric{service,instance,metric}`.

## 8. Scheduled NMS reports with PDF

- **New sections:**
  - Network availability & SLA;
  - Capacity risks;
  - Wireless usage;
  - Network alerts;
  - Configuration changes;
  - Rogue access points.
- **PDF copy:** every run also produces a PDF (WeasyPrint), which is never allowed to fetch a remote resource. It is
  attached to the email (up to 8 MB) and can be downloaded from the Reports page.
- **Fallback:** if the PDF engine fails, the HTML report still goes out.

## 9. SNMP speed (inside pysnmp)

- **Profile:** a production poller during the controller's wireless job spends nearly all its CPU in pyasn1's BER
  decoder (`clone`, `_moveSizeSpec`, `valueDecoder`). The application's own code is a few percent.
- **Fix:** decode less.
  - When the controller answers the CISCO-LWAPP client table, the duplicate AIRESPACE client columns are not walked:
    SSID, status, reason, user name, AP MAC, and two unused packet counters.
  - That takes a client poll from 27 to 20 columns per client, about 26 % fewer values to decode.
- **Per-value conversion:** about 33 % faster (0.272 → 0.182 s per 100,000 values).
- **Still to do:** measure the production effect after the deploy (the wireless job's `wireless_client` group
  duration and poller CPU).

## Deployment

```bash
./scripts/deploy.sh --apply
```

- **Migrations** (all additive):
  - PostgreSQL 0030 (SSH credentials, config snapshots), 0031 (rogues), 0032 (report PDF);
  - ClickHouse 19 (flows), 20 (self-metrics).
- **New service:** `flows`, bound to loopback until `FLOW_BIND_IP` is set.
- **Backend image changes:** adds `asyncssh` and `weasyprint` (+ pango / harfbuzz / DejaVu fonts). Re-run the image
  scan (CI `images` job / Trivy) on the new image.
- **New settings:**
  - `CONFIG_BACKUP_INTERVAL_HOURS`;
  - `CONFIG_BACKUP_TIMEOUT_SECONDS`;
  - `CONFIG_BACKUP_CONCURRENCY`;
  - `CONFIG_BACKUP_RETENTION_DAYS`;
  - `SWITCH_WIRELESS_GROUP_CONCURRENCY` (now 5).

## Tests

| Area | File |
|---|---|
| Topology and dependency alerting | `tests/test_topology_impact.py` |
| Anomaly rules | `tests/test_anomaly.py` |
| Capacity forecasts | `tests/test_capacity_more.py` |
| Config backup, against a real local SSH server | `tests/test_config_backup.py` |
| Flow decoders, collector and API | `tests/test_flows.py` |
| Rogues, PoE, floors, traps | `tests/test_wireless_more.py` |
| Self-monitoring | `tests/test_selfmon.py` |
| Reports and PDF | `tests/test_nms_reports.py` |

- **Backend:** full suite, 568 passed.
- **Frontend:** 45 tests pass; type check and build clean.
- **Browser check:** every new page was checked against seeded data on a local run.
