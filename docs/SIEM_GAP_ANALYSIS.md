# SIEM gap analysis, 2026-11-02

Statuses:

| Status | Meaning |
|---|---|
| **Complete** | implemented and verified |
| **Partial** | some functionality exists |
| **Missing** | not implemented |
| **Broken** | exists but does not work correctly |
| **Needs Refactoring** | works but needs architectural improvement |
| **Needs Testing** | implemented but not validated enough |

Priorities run from P0 (critical) to P3, as in [SIEM_IMPLEMENTATION_ROADMAP.md](SIEM_IMPLEMENTATION_ROADMAP.md).
Rows marked **→ done** were implemented in this pass; the "Change log" at the end lists the files and tests.

## A. Log collection

| Capability | Status | Where / what exists | Gap and approach | Priority |
|---|---|---|---|---|
| Syslog UDP / TCP | Complete | ingress (rsyslog) → `syslog_server.py` | — | — |
| Syslog over TLS | Missing | — | rsyslog `gtls` input on 6514 in `deploy/ingress` with a CA-signed certificate, client-cert option | P1 |
| RFC 3164 / RFC 5424 | Partial | envelopes stripped before FortiGate key=value parsing; header fields (host, app, structured data) not kept for generic sources | keep host / app / msgid from the 5424 header in the generic and network-device parsers | P1 |
| FortiGate syslog | Complete | `ingest/parser.py`, `normalize.py` | — | — |
| Cisco IOS / IOS-XE / NX-OS / C9800 syslog | Missing **→ done** | stored as plain text only | parser for `%FACILITY-SEV-MNEMONIC` messages: severity, interface, IPs, user, config / login / routing / HSRP / STP / port-security / DHCP-snooping / rogue-AP events | P1 |
| Ruckus FastIron syslog | Missing **→ done** | plain text | parser for ICX log lines (login, config change, port / STP / MAC / DHCP events) | P1 |
| Ruckus wireless (SmartZone) syslog | Missing | plain text | parser after a sample of SZ log formats is available (formats differ by release) | P2 |
| NetFlow v5 / v9, IPFIX, sFlow | Missing | — | UDP flow collector process writing a `flows` table (or `traffic` events) with template cache, size limits, exporter allow-list; see roadmap R5 | P2 |
| SNMP traps | Complete (NMS) | `snmp_traps.py`, `snmp_traps` table | not yet visible in Event Explorer: expose traps as events | P2 |
| REST API collectors | Partial | FortiGate REST (health, policies, counters), PAN-OS XML | cloud / SaaS APIs missing | P3 |
| Windows Event Logs | Complete | `generic.windows` (NXLog / Winlogbeat / Snare) | — | — |
| Linux journald / rsyslog / auditd | Partial | arrive as plain syslog (message only) | auditd / sshd / sudo parser | P2 |
| DNS logs | Partial | FortiGate DNS filter, CEF DNS | BIND / Windows DNS / Infoblox parsers | P2 |
| DHCP logs | Missing | — | Windows DHCP / ISC dhcpd parser (lease → IP-MAC-host mapping for assets) | P2 |
| Cloud security logs (Azure, AWS) | Missing | — | pull collectors with read-only credentials | P3 |
| Custom log ingestion | Partial | CEF / plain syslog; no user-defined parser | JSON-lines HTTP ingest endpoint with per-source token, and regex / KV parser definitions | P2 |
| Buffering / backpressure / dead letter | Complete | `ingest/pipeline.py`, `deadletter.py` | — | — |
| Collector health | Complete | Log Sources page, ingestion counters, `syslog counters` log lines | — | — |
| Event loss detection | Partial | `log_feed_gap` rule (FortiGate), counters for dropped / dead-lettered | per-source silence detection for generic sources | P1 |

## B. Parsing and normalization

| Capability | Status | Notes / gap | Priority |
|---|---|---|---|
| Vendor parsers | Partial **→ improved** | FortiGate, PAN-OS, Windows, CEF; Cisco and Ruckus syslog added this pass | P1 |
| JSON parsing | Partial | Windows JSON only; generic JSON-lines ingest missing | P2 |
| Regex / key-value parsing | Partial | built-in only; no administrator-defined parsers | P2 |
| CEF | Complete | `generic.cef` | — |
| Timestamp normalization | Complete | event time in UTC, ingest time kept | — |
| Severity normalization | Complete | normalized severity + `orig_severity` | — |
| IP / port / protocol extraction | Complete for FortiGate / PAN / CEF; **→ done** for Cisco / Ruckus where the message carries them | — |
| Event categorization | Complete | category / event_type / event_subtype | — |
| Raw event preservation | Complete | `raw` column (ZSTD) | — |
| Parser error handling | Complete | falls back to plain syslog, never drops; counters | — |
| Parser testing | Complete | fixtures under `tests/fixtures` | — |
| Canonical schema (OCSF / ECS) | Partial | own FortiGate-shaped schema used everywhere | add an ECS / OCSF field mapping layer for export and search aliases, not a storage change (would break every query) | P2 |
| Custom parser support | Missing | — | regex / KV parser definitions per log source | P2 |

## C. Network security analytics

| Capability | Status | Where | Gap | Priority |
|---|---|---|---|---|
| Top talkers / destinations / ports / apps, traffic volume, protocol distribution, allow / deny | Complete | Top-N pages, dashboard | — | — |
| Application identification | Complete (from FortiGate app-control) | `app`, `app_cat` | — | — |
| Inbound / outbound, east-west / north-south | Partial | internal CIDRs known (`INTERNAL_CIDRS`); no direction breakdown view | direction field in queries + dashboard tile | P2 |
| Traffic baselines | Complete | `volume_baseline` rule (7-day per host) | — | — |
| Connection duration | Partial | `duration` stored; no analytics view | P3 |
| Unusual outbound connections | Complete | `outbound_volume`, `new_country`, `new_port` | — | — |
| Internal port scan / host sweep | Complete | `port_scan`, `host_sweep` (any direction) | — | — |
| External port scan (inbound) | Partial **→ done** | `port_scan` counts any source | YAML rule NET-1002 limited to external → internal | P1 |
| Suspicious DNS | Complete | DNS tunnel / spike / NXDOMAIN / new domain | — | — |
| Data exfiltration | Complete | outbound volume + baseline | — | — |
| C2 beaconing | Complete | `beaconing` | — | — |
| Segmentation violations (east-west) | Missing **→ done** | — | YAML rule NET-3003 (internal fan-out on admin ports) | P1 |
| NetFlow-based analytics | Missing | — | depends on the flow collector | P2 |

## D. Threat detection engine

| Capability | Status | Notes | Priority |
|---|---|---|---|
| Rule-based, threshold, time-window, aggregation | Complete | Python rules + custom pipeline rules | — |
| Declarative rule format (YAML) | Missing **→ done** | rules were Python functions or query strings | `app/detection/`: schema, loader, validator, SQL compiler, executor, test runner; rules in `backend/rules/*.yml` | P1 |
| Stateful / multi-source correlation | Partial | incident correlation by entity; `multi_site`, `peer_anomaly` | sequence rules (A then B within T by same entity) | P2 |
| Sequence-based detection | Missing | — | P2 |
| Suppression / allowlisting | Complete for suppressions; **→ done** allowlists per YAML rule (`allowlist:` CIDRs / values) | — |
| Rule versioning | Missing **→ done** | YAML `version` + content hash recorded in the rule row | — |
| Rule testing | Partial **→ done** | preview for custom rules; YAML rules ship test cases run in CI and from the API | — |
| Rule performance monitoring | Missing **→ done** | last duration / matches per YAML rule exposed in the API | — |
| False-positive management | Complete | closure verdicts → per-rule FP rate | — |
| Alert generation, dedupe, auto-resolve | Complete | `alerts/engine.py` | — |

### The 20 requested detections

| # | Detection | Status |
|---|---|---|
| 1 | Internal port scan | Complete (`port_scan`) |
| 2 | External port scan | **→ done** (NET-1002) |
| 3 | Host scan | Complete (`host_sweep`) |
| 4 | Firewall deny spike | Complete (`denied_burst`) |
| 5 | VPN brute force | Complete (`vpn_bruteforce`) |
| 6 | Suspicious outbound connections | Complete (`outbound_volume`, `new_port`, `new_country`) |
| 7 | DNS tunnelling | Complete (`dns_tunnel`) |
| 8 | Data exfiltration | Complete (`outbound_volume`, `volume_baseline`) |
| 9 | Rogue DHCP server | **→ done** (NET-2001, Cisco DHCP snooping / Ruckus) |
| 10 | Unauthorized device | **→ done** (NET-2006, port-security violations); `switch_port_up_unexpected` (SNMP) existed |
| 11 | Firewall configuration modification | Complete (`config_change`, `risky_config_change`); **→ done** for switches / routers (NET-2007) |
| 12 | Suspicious administrator login | Complete (`admin_login_fail`, identity rules); **→ done** for network devices (NET-2008) |
| 13 | Abnormal east-west traffic | **→ done** (NET-3003) |
| 14 | Known malicious IP | Complete (`ti_match`) |
| 15 | C2 beaconing | Complete (`beaconing`) |
| 16 | BGP adjacency changes | Complete for FortiGate (`bgp_peer_down`) and SNMP (`switch_routing_neighbor`); **→ done** for router syslog (NET-2003) |
| 17 | OSPF adjacency changes | Partial (SNMP); **→ done** for syslog (NET-2002) |
| 18 | Wireless rogue AP | **→ done** (NET-2009, C9800 rogue syslog; message text varies by release, matched on "rogue") |
| 19 | Unexpected protocol usage | **→ done** (NET-3001: telnet / TFTP / SMB / RDP / database ports leaving the network) |
| 20 | Traffic outside business hours | Partial (`admin_off_hours_change`); **→ done** (NET-3002) |
| + | HSRP / VRRP failover, STP guard events | **→ done** (NET-2004, NET-2005) |

## E. Threat intelligence

| Capability | Status | Gap | Priority |
|---|---|---|---|
| IP / CIDR / domain IOCs, feed ingestion, ingest-time matching, retroactive hunt | Complete | — | — |
| URL and file-hash indicators | Missing | add `url`, `sha256` types; match URL / threat fields | P2 |
| Indicator expiration, confidence, source attribution | Partial (feed attribution only) | `expires_at`, `confidence` columns + matcher filter | P2 |
| MISP, OTX, AbuseIPDB, URLhaus, VirusTotal | Missing | connector per provider, keys from `.env`, cached lookups, rate limits; no internal data sent unless enabled | P2 |
| Historical IOC search | Complete (Hunt) | — | — |

## F. UEBA

| Capability | Status | Notes |
|---|---|---|
| User login baseline / unusual login / impossible travel | Complete | `identity.py`, `impossible_travel` |
| Device traffic baseline, new destination country / port | Complete | `volume_baseline`, `new_country`, `new_port` |
| Rare destination | Partial | `new_domain`, `new_country`; no per-host rare-destination score (P2) |
| New device detection | Partial | assets learned with `first_seen`; no alert (P2: `asset_new` rule) |
| Asset / user risk scoring | Missing | P2: score = weighted open alerts × criticality, explained |
| Statistical anomaly detection | Partial | baselines; no seasonal model (P3) |

## G. Firewall and network device security

| Capability | Status | Notes |
|---|---|---|
| FortiGate integration, policy analysis, hit counts, unused / shadowed / redundant | Complete | `policy/*` |
| Duplicate policy, any-to-any | Complete | shadow analysis + `risky_config_change` |
| NAT analysis | Partial | NAT fields stored; no NAT view (P3) |
| VPN, IPS events, config change, HA, BGP | Complete | vpnmon, security events, drift, SNMP vendor health, bgp |
| Cisco routing / OSPF / BGP / HSRP / STP / VLAN events | Partial (SNMP) **→ done** (syslog) | |
| Rogue DHCP, ARP anomaly | **→ done** rogue DHCP (syslog); ARP inspection (`%SW_DAI`) mapped; ARP anomaly from flows missing (P2) | |
| Wireless rogue AP | **→ done** (syslog) | SNMP rogue table not mapped (P2) |

## H. Incident management

| Capability | Status | Gap | Priority |
|---|---|---|---|
| Queue, severity, assignment, timeline, comments, evidence, tasks, audit trail, closure reasons, SLA | Complete | — | — |
| Status set | Partial | `open / in_progress / resolved / closed`; requested statuses *investigating, contained, false positive* missing | P1 |
| Priority (separate from severity), tags | Missing | add columns, filters | P1 |
| Alert grouping / dedupe, related events, asset / TI context | Complete | — | — |
| Incident export | Partial | report export exists; per-incident JSON / PDF export missing | P2 |

## I. Threat hunting

| Capability | Status | Notes |
|---|---|---|
| Search by IP / domain / host / user / port / protocol / time, multi-source, aggregations | Complete | query language + pipeline |
| Saved queries, hunting library | Complete | |
| Query history | Partial | per-browser history only (P2: server-side per user) |
| IOC pivoting | Complete | entity pages, TI hunt |
| PCAP investigation | Missing | P3: object storage needed; not justified yet |

## J. Assets and topology

| Capability | Status | Notes |
|---|---|---|
| Discovery, IP / MAC / host / OS / user, criticality, owner, tags | Complete | `assets` (learned) + SNMP inventory |
| Vendor / firmware inventory for network devices | Complete | NMS inventory analytics |
| Site / VLAN mapping | Partial | site on devices; VLAN per switch port; no asset → VLAN join (P2) |
| Communication history | Complete | entity pages / explorer |
| Topology graph | Partial | LLDP / CDP switch graph (ECharts); hosts / subnets / zones not drawn (P2) |
| Zones, asset risk score | Missing | P2 |

## K. Dashboards

| Dashboard | Status |
|---|---|
| SOC overview, network security (top-N, DNS, geo, VPN), firewall, incidents, TI, assets | Complete (real data) |
| Data source / collector health | Complete (Log Sources, SNMP polling health) |
| Detection engine health | Partial **→ done** (YAML rule run stats); built-in rules have last-run result only in logs |
| SIEM infrastructure monitoring | Partial (`/api/metrics`, health endpoints; no Grafana dashboards) |
| Mock data | Demo mode only, flagged `source=demo` with a banner; no mock data in production paths |

## L. SOAR

| Capability | Status | Notes |
|---|---|---|
| Notifications (email, Slack, Teams, webhook) | Complete | |
| Playbooks with dry-run test, audit | Complete | `automation.py` |
| FortiGate IP blocking / address object / blocklist | Partial | CLI suggestion only; IaC can push address objects through approval, not wired to playbooks (P2) |
| Ticket creation, EDR isolation | Missing | P3: via webhook templates first |
| Approval workflow, preview, rollback | Complete in IaC; missing for playbook actions | P2 |

## Change log for this pass

See the bottom of [SIEM_IMPLEMENTATION_ROADMAP.md](SIEM_IMPLEMENTATION_ROADMAP.md#delivered-in-this-pass).
