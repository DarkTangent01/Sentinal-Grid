# Existing features (inventory), 2026-11-02

Every row names where the feature lives, so it can be checked. "Verified" means covered by the automated suite (434
backend tests and 39 frontend tests passing on 2026-11-02) and, where stated, running in production.

## Sentinel Grid (SIEM)

| Feature | Where | Verified |
|---|---|---|
| Syslog UDP / TCP (RFC 6587 octet counting) with rsyslog ingress relay and disk queue | `deploy/ingress/rsyslog.conf`, `app/syslog_server.py` | tests and production |
| FortiGate key=value parser, RFC 3164 / 5424 envelope stripping | `app/ingest/parser.py`, `normalize.py` | tests, production (3 FortiGates) |
| Palo Alto PAN-OS syslog parser and read-only XML API | `app/ingest/panos.py`, `app/paloalto.py` | tests (fixtures) |
| Windows Security events (NXLog / Winlogbeat JSON, Snare), CEF, plain syslog | `app/ingest/generic.py` | tests |
| Normalised event model (ClickHouse `events`) with raw line kept, dedupe by `event_id` | `app/db/ch_schema.py`, `ingest/pipeline.py` | tests |
| Backpressure, retries, dead-letter spool and replay | `ingest/pipeline.py`, `ingest/deadletter.py` | tests |
| Enrichment: threat intel (4 feeds + manual IOCs: IP, CIDR, domain), GeoIP / ASN, assets | `app/enrich/*`, `app/assets.py` | tests |
| 42 security detection rules (scan, sweep, deny burst, beaconing, DNS tunnel / spike / NXDOMAIN / new domain, outbound volume, 7-day volume baseline, new country / port, VPN brute force, impossible travel, admin / config changes, identity, Windows, TACACS+) | `app/alerts/engine.py`, `rules.py`, `identity.py`, `tacacs/alerts.py` | tests |
| Custom detections (scheduled pipeline queries) and Sigma import | `app/alerts/custom.py`, `app/sigma.py`, `/api/detections` | tests |
| Suppressions, rule effectiveness (false-positive rate per rule) | `alert_suppressions`, `app/api/soc.py` | tests |
| MITRE ATT&CK mapping on every rule | `rules.py` `mitre` | tests |
| Incident correlation (entity, 24 h), case management (assignee, SLA, comments, evidence, tasks, closure verdicts) | `app/incidents.py`, `app/api/soc.py` | tests |
| Search query language, saved / scheduled searches, hunting queries, bookmarks, workbooks, watchlists, entity graph | `app/analytics/ql.py`, `pipeline.py`, `app/api/hunt.py` | tests |
| Identity analytics (VPN users, unusual logins, admin activity) | `app/identity.py`, `app/vpnmon.py` | tests |
| Automation playbooks (assign, status, severity, comment, notify, enrich, watchlist, suggest_block CLI, run query) with dry-run test | `app/automation.py` | tests |
| Notifications: Slack, Teams, email, signed webhooks, outbox with retries | `app/notify.py` | tests |
| Compliance evidence (CERT-In, ISO 27001, PCI DSS 4, NIST CSF 2), scheduled reports | `app/compliance.py`, `app/reports.py` | tests |
| Policy analytics, shadow / redundant policy detection, config drift, hardening plans, IaC (approval-gated writes) | `app/policy/*`, `drift.py`, `hardening/*`, `iac/*` | tests |
| AI assistant (optional, Claude API) | `app/ai.py` | tests (mocked) |

## Sentinel NMS (network operations, feeds the SIEM with network context)

| Feature | Where | Verified |
|---|---|---|
| SNMP polling, multi-vendor adapters, fingerprints, backoff | `app/switches/*` | tests, production (11 Catalyst + 1 C9800) |
| SNMP trap / inform receiver (v1/v2c/v3) and trap alerts | `app/snmp_traps.py`, `app/nms/alerts.py` | tests over UDP, production listener |
| LLDP / CDP topology and path check | `app/switches/topology.py`, `pages/switches/Topology.tsx` | tests |
| Wireless (Catalyst 9800): APs, radios, clients, RF analytics | `app/wireless/*` | tests, production |
| ISP / WAN, firewall health, VPN tunnels, BGP (incl. prefix / leak analysis) | `app/wan*.py`, `fwhealth.py`, `vpnmon.py`, `bgp*.py` | tests, production |
| Service checks, maintenance windows, dependencies, NMS analytics | `app/nms/*` | tests, production |
| TACACS+ AAA | `app/tacacs/*` | tests (simulated server) |

## Platform

| Feature | Where | Verified |
|---|---|---|
| Local auth (Argon2, lockout, CSRF, session versioning), roles, product access, NMS site scope | `app/api/auth.py`, `products.py` | tests |
| Audit log (configuration changes, access denials, OID tests) | `audit_log`, `app/api/deps.py:audit` | tests |
| Retention per category, ClickHouse TTLs | `app/retention.py`, `ch_schema.py` | tests |
| Observability: request IDs, access log, `/api/metrics`, `/api/health`, `/api/ready` | `app/observability.py`, `main.py` | tests |
| CI (lint, test, audit, build) | `.github/workflows/ci.yml` | defined; runs on GitHub |
