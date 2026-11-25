# Module ownership matrix

Owners:
- **GRID**: SIEM only.
- **NMS**: network management only.
- **PLATFORM**: generic infrastructure with no business logic. It may be shared as a library, never as a service holding
  both products' data.
- **SPLIT**: today it mixes both products and must be divided.

Unused: none found (see [SEPARATION_AUDIT.md](SEPARATION_AUDIT.md) §2.4).

## Backend (`backend/app`)

| Module | Owner | Target / action |
|---|---|---|
| `ingest/` (syslog, FortiGate, PAN-OS, Zeek, JSON, LEEF, Linux, HTTP ingest), `syslog_server`, `api/ingest` | GRID (receiver) + PLATFORM (format parsers) | Parsers become `shared/logparsing` (pure functions: line → normalised record). The receiver, pipeline, dedupe and ClickHouse sink stay in GRID. NMS gets its own receiver for network-operational classes (MIGRATION_PLAN phase 6) |
| `ingest/netdev.py` (Cisco / Ruckus syslog) | PLATFORM parser; consumed by NMS (system / routing / interface) and GRID (security kinds) | Both receivers use it; each keeps its own categories |
| `detection/`, `sigma`, `mitre`, `tuning`, `api/yaml_rules` | GRID | Move |
| `enrich/` (TI, GeoIP, enricher) | GRID | Move. NMS uses only GeoIP AS lookup (`isp`): give NMS its own small GeoIP reader over the same `.mmdb` files (platform utility) |
| `analytics/` (filters, queries, ngen, ql, pipeline) | GRID | Move. NMS callers (`api/hardening`, `api/isp`, `api/policies`, `policy/store`) switch to an NMS event-query module over the NMS ClickHouse database |
| `incidents`, `investigate_brief`, `response`, `risk`, `socmetrics`, `api/soc`, `api/siem` | GRID | Move. NMS `wan` uses only the SLA timer helper: copy it into NMS (about 30 lines). `drift → correlate_alerts` goes; drift alerts stay NMS faults |
| `identity`, `zeek`, `watchlists`, `searches`, `automation` (SIEM automation rules), `ai`, `compliance`, `assets`, `content` | GRID | Move. `identity` stops importing `vpnmon` helpers (copy the time helper). `bgp → watchlists` goes: NMS has no watchlists |
| `api/analytics`, `api/context`, `api/hunt`, `api/identity` | GRID | Move. `api/context → drift` goes; the optional integration provides device context instead |
| `api/ops` | SPLIT | Ingest / log-source health → GRID; firewall-health, BGP and VPN feed status → NMS operations page |
| `switches/`, `wireless/`, `snmp_profiles`, `snmp_traps`, `flows/`, `nms/`, `selfmon`, `icmp`, `isp`, `wan`, `wan_alerts`, `wan_metrics` | NMS | Move. `selfmon` stops importing `ingest.pipeline.rss_mib` (platform utility) |
| `bgp`, `bgp_analysis`, `vpnmon`, `fwhealth` | NMS | Move; read the NMS event store instead of the SIEM's |
| `policy/` (policy analytics, shadow), `hardening/`, `drift`, `iac/`, `netcompliance/`, `configs/`, `access/`, `playbooks/`, `tacacs/` | NMS | Move |
| `fortigate/`, `paloalto` (REST / XML API clients) | NMS (device management) | Move to `nms/vendors/`. The SIEM should need no firewall API: it identifies log senders by source address (log sources). To confirm in phase 3: response actions name a firewall by id for the commands they generate, which would need a firewall list (name / vendor / address only) on the GRID side |
| `api/firewalls` | NMS (registry with API tokens) | Move. The SIEM keeps "log sources" for sender identity |
| `alerts/` (engine, rules, custom) | SPLIT | The engine framework (rule registry, evaluation loop, suppression, deduplication, notification hand-off) → PLATFORM library. SIEM rules → GRID; NMS rules → NMS. Each product keeps its own `alerts`, `alert_rules` and `alert_suppressions` tables |
| `notify` | PLATFORM (channels) | Library. Each product keeps its own channel and rule tables |
| `reports` | SPLIT | Framework (scheduling, HTML / PDF rendering, email) → PLATFORM; sections → each product |
| `retention` | SPLIT | Framework → PLATFORM; each product registers its own tables |
| `worker` | SPLIT | Each product has its own worker entry point and loop plan; the poller stays NMS |
| `main` | SPLIT | Two application factories (GRID API, NMS API); the access gateway stays NMS |
| `bootstrap`, `migrate`, `register`, `demo`, `devserver` | SPLIT | Per product. `demo` (synthetic events) → GRID only; `register` (firewall CLI) → NMS; the development server per product |
| `config` | SPLIT | Each product has its own Settings class; a PLATFORM base for database / ClickHouse / secret-file loading |
| `db/` (`pg.py`, `ch.py`) | PLATFORM | Connection helpers library |
| `db/models.py`, `db/ch_schema.py` | SPLIT | Per-product model and schema modules; no product imports the other's models |
| `security` (password hashing, session JWT, TokenCipher), `netguard`, `secret_files`, `logging_setup`, `observability`, `rotate_keys` | PLATFORM | Library |
| `products` (product boundary inside one app) | Obsolete after the split | Each application serves one product; the site scope (`site_allowed`) stays in NMS |
| `api/auth`, `api/admin`, `api/deps` | PLATFORM pattern, per-product instance | Each product has its own login, users, CSRF and session cookie, built on shared auth primitives |

## Frontend (`frontend/src`)

| Area | Owner |
|---|---|
| `pages/Dashboard`, `TopN`, `Web`, `Dns`, `Geo`, `Explorer`, `Security`, `ThreatIntel`, `Detections`, `RulePack`, `Watchlists`, `Searches`, `Search`, `Hunting`, `EntityGraph`, `Workbooks`, `Automation`, `Vpn`, `Identity`, `Compliance`, `Investigate`, `Incidents`, `Soc`, `NetworkSecurity` | GRID |
| `pages/nms/*`, `switches/*`, `snmp/*`, `wireless/*`, `wan/*` (ISP), `tacacs/*`, `iac/*`, `Bgp`, `FirewallHealth`, `VpnTunnels`, `Policies`, `PolicyDetail`, `Shadow`, `Drift`, `Hardening`, `Firewalls` | NMS |
| `Alerts`, `Reports`, `Notifications`, `Settings`, `Assets`, `LogSources` | SPLIT: one per product. `Assets` and `LogSources` → GRID; NMS has device inventory and its own alerts / reports / notifications / settings |
| `ProductSelect`, `lib/products.ts` (product switching) | Obsolete after the split (cross-product links via the optional integration instead) |
| `components/ui`, `Chart`, `charts`, `WorldMap`, `Layout`, `Sidebar`, `lib/api`, `format`, `theme`, `chartData`, `echarts` | PLATFORM (shared UI package); the sidebar takes the navigation tree as data |

## Deployment

| Service | Owner |
|---|---|
| `ingress` (rsyslog relay) | PLATFORM edge: fans out to both products' receivers |
| `syslog` | GRID |
| `api`, `worker` | SPLIT → `grid-api` / `grid-worker` and `nms-api` / `nms-worker` |
| `poller`, `traps`, `flows`, `access`, `ansible`, `tacacs` | NMS |
| `web` | SPLIT → `grid-web`, `nms-web` (two builds; one nginx can serve both on different host names or ports) |
| `postgres`, `clickhouse` | PLATFORM infrastructure, with a separate database and user per product |
| `migrate` | SPLIT → one migration job per product |

## Tests (`backend/tests`)

| Owner | Files |
|---|---|
| GRID | `test_detection_yaml`, `test_hunt_api`, `test_identity`, `test_ingest_api`, `test_ingress_relay`, `test_parsers`, `test_parsing`, `test_pipeline`, `test_ngen_*`, `test_soc`, `test_ti_connectors`, `test_paloalto` (log parts), `test_storage_analytics` (events) |
| NMS | `test_switches`, `test_snmp`, `test_wireless*`, `test_topology_impact`, `test_anomaly`, `test_capacity_more`, `test_config_backup`, `test_device_access`, `test_nms*`, `test_flows`, `test_icmp`, `test_isp`, `test_wan`, `test_bgp`, `test_iac`, `test_tacacs`, `test_netcompliance`, `test_policy_*`, `test_hardening`, `test_fortigate_client`, `test_selfmon`, `test_netdev_parser` |
| SPLIT | `test_api`, `test_alerts`, `test_ops`, `test_platform`, `test_products`, `test_modernization`, `test_security_regressions`, `test_secret_files`, `test_performance` |

## Additions from phases 3–4 (2026-11-23)

| Module | Owner |
|---|---|
| `app/platform/*` (eventquery, geoip, procstats, timeutil, sla) | shared (imports no product) |
| `alerts/engine.py`, `reports.py`, `api/notifications.py`, `api/reports.py` | shared frameworks / services |
| `alerts/siem.py`, `alerts/rules.py`, `analytics/report_sections.py` | Sentinel Grid |
| `alerts/nms.py`, `nms/report_sections.py`, `api/netops.py`, `register.py`, `traffic/*`, `api/traffic.py` (application & protocol intelligence) | Sentinel NMS |
| `composition.py`, `alerts/combined.py`, `main.py`, `worker.py`, `devserver.py`, `demo.py`, `bootstrap.py`, `migrate.py`, `access/asgi.py` | composition hubs (may import both; nothing imports them) |

The authoritative, test-enforced list is `backend/tests/test_product_boundaries.py`.
