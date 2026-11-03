# SIEM implementation roadmap, 2026-11-02

The priorities come from [SIEM_GAP_ANALYSIS.md](SIEM_GAP_ANALYSIS.md) and the production facts:
- **Production data sources:** 3 FortiGates, 11 Cisco Catalyst switches and 1 Catalyst 9800 controller.
- **Collection:** syslog and SNMP already reach the platform.
- **Missing:** no flow exporters, Zeek or Suricata yet.

Nothing in the gap list is broken. The P0 items are the security findings in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

| ID | Priority | Item | Why now | Status |
|---|---|---|---|---|
| R1 | P1 | **Network-device syslog parsing** (Cisco IOS / IOS-XE / NX-OS / C9800, Ruckus FastIron) | The production switches and controller can send syslog today, but it was stored as plain text, so routing, HSRP, STP, port-security, DHCP-snooping, login and configuration events couldn't be detected | **Done in this pass** |
| R1b | P1 | **YAML detection engine** with loader, validator, compiler, executor, versioning, run statistics, test framework and rule pack covering the missing detections | Detections were Python-only; 9 of the 20 requested detections were missing | **Done in this pass** |
| R2 | P0 / P1 | Syslog over TLS (rsyslog `gtls`, 6514) | SA-1 (spoofing / eavesdropping) | Next |
| R3 | P1 | Secret redaction for every generic source; per-source silence detection | SA-5, event-loss detection gap | Next |
| R4 | P1 | Incident statuses (*investigating, contained, false positive*), priority, tags | SD-4 | Next |
| R5 | P2 | Flow collector: NetFlow v5 / v9, IPFIX, sFlow, to a `flows` table + flow-based scan / east-west rules | SD-7; needs exporters configured on the switches / firewalls | Planned |
| R6 | P2 | TI: URL / hash indicators, expiry, confidence; MISP / OTX / AbuseIPDB / URLhaus / VirusTotal connectors (keys optional) | Gap E | Planned |
| R7 | P2 | Playbook `block_ip` → IaC address-object plan (approval, dry run, rollback) | Gap L, SD-5 | Planned |
| R8 | P2 | Site scope for Grid data | SA-3 | Planned |
| R9 | P2 | Zeek / Suricata EVE ingestion, DHCP / DNS / auditd parsers, JSON-lines HTTP ingest, ECS / OCSF alias map, sequence rules, asset / user risk scores | Gaps A, B, D, F | Planned |
| R10 | P3 | Multi-tenancy, cloud collectors, PCAP (object storage), EDR / ticketing integrations, HA | Not needed for the current single-organisation deployment | Backlog |

## Broker decision

No Kafka / Redpanda for now. Measured ingestion headroom ([PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md)), the rsyslog disk queue, in-process backpressure and the dead-letter spool already cover buffering, retry and replay for one host. Introduce a broker when one of these becomes true:
- several parser hosts are needed;
- sustained ingestion approaches the measured single-host limit;
- a second consumer of raw events (for example a data lake) must read independently.

## Delivered in this pass

| Item | Files | Tests |
|---|---|---|
| Network-device syslog parser (Cisco, Ruckus) with secret redaction; new log-source kind `netdev`, auto-detected for `syslog` sources | `backend/app/ingest/netdev.py`, `ingest/generic.py`, `api/ops.py`, `frontend/src/pages/LogSources.tsx` | `tests/test_netdev_parser.py` |
| YAML detection engine (schema, field allow-list, compiler to parameterised ClickHouse SQL, executor in the alert engine, allowlists, versions, run statistics, test runner) | `backend/app/detection/` | `tests/test_detection_yaml.py` |
| Rule pack NET-1002, NET-2001…2009, NET-3001…3003 with test cases, false positives, data sources, investigation steps. NET-3001 ships *experimental* (disabled): it matched 87 host / port pairs in one pass over the demo data, so it should be dry-run on real traffic first | `backend/rules/*.yml` | every rule's embedded tests run in the suite; all 13 ran in the dev engine at 3-8 ms each |
| Packaging fix: the backend image now copies `backend/rules` (without it, the rule import would fail at startup) | `backend/Dockerfile` | — |
| API `/api/detections/yaml` (list, detail, validate, test, dry run, custom rules with versions / rollback; enable and threshold through `/api/alert-rules`) and the Detections page "Rule pack" card with editor | `app/api/yaml_rules.py`, `app/api/alerts.py`, `frontend/src/pages/RulePack.tsx`, `Detections.tsx` | `test_yaml_rules_api`, `src/pages/ruleFormat.test.ts` |
