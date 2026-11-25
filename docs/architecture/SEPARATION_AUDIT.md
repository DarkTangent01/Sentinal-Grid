# Separation audit: Sentinel Grid (SIEM) and Sentinel NMS

Date: 2026-11-23. Scope: the whole repository.

Method:
- an AST import graph of all backend modules (`app/`, about 55,000 lines, 75 top-level modules and packages);
- route registration (`main.py`, `products.py PATH_PRODUCT`);
- PostgreSQL models and ClickHouse schema with their readers and writers;
- worker loop plan (`worker.py loop_plan`);
- Compose services, frontend routes and navigation (`App.tsx`, `lib/products.ts`);
- tests and CI.

**Nothing was changed in this phase.**

## 1. Existing architecture

| Layer | Today |
|---|---|
| Backend | **One** FastAPI application (`app.main:create_app`) mounts every router of both products (31 routers), plus the access gateway as a second entry point (`create_app("access")`). Product separation is a runtime check: `products.required_product(path)` refuses an API path for a user without that product. |
| Workers | **One** worker code base (`app.worker`) with roles: `core` runs everything except SNMP, `snmp` runs the poller (3 replicas). Both roles mix SIEM and NMS loops: alert evaluation for both products, retention for both, TI feeds next to WAN / ICMP / TACACS / IaC / wireless / config backup. A separate `ansible` runner is NMS only. |
| Ingestion | One syslog pipeline (`ingress` rsyslog relay → `syslog` service → `ingest/`) writes **every** log, both firewall security logs and network-device operational logs, into one ClickHouse table `events`. |
| PostgreSQL | **One** database and one Alembic history (0001–0036). 116 tables, owned by both products, in one `public` schema, with one application user. |
| ClickHouse | **One** database. 38 tables and materialized views; `events` and its rollups are read by both products. One migration history (`ch_schema.py`, 1–21). |
| Identity | **One** `users` table with `products` (grid / nms), `sites`, `iac_roles`, `tacacs_roles`, `nms_roles`. One session cookie for both products, plus a product selector at sign-in. |
| Frontend | **One** React SPA. The sidebar switches between two navigation trees (`NAV.grid`, `NAV.nms`); `OWN` decides which pages belong to which product. Shared pages (Alerts, Reports, Assets, Log Sources, Notifications, Settings) serve both through `?product=`. |
| Deployment | **One** Compose project (`docker-compose.yml`: 14 services, one of them the one-shot `migrate`) and one Kubernetes overlay. A single `deploy.sh` deploys everything; there is no way to restart one product alone. |

## 2. Coupling found (evidence)

### 2.1 Direct imports between product modules: 31

| From | To | What is used | Kind |
|---|---|---|---|
| NMS `api/hardening`, `api/isp`, `api/policies`, `policy/store` | SIEM `analytics.filters` | `EventFilter`, `table()`: queries over the firewall `events` table | **data** (shared event store) |
| NMS `bgp`, `bgp_analysis`, `fwhealth`, `isp`, `vpnmon`, `netcompliance/checks` | ClickHouse `events` (FortiGate logs) | VPN tunnel up / down, SD-WAN health, BGP events, ISP failover, policy hit counters derived from **firewall logs** | **data** |
| NMS `wan`, `api/wan` | SIEM `incidents` | `SLA`, `sla_state` (an SLA timer helper) | code (small helper) |
| NMS `drift` | SIEM `incidents` | `correlate_alerts` (attaches drift alerts to incidents) | behaviour |
| NMS `bgp` | SIEM `watchlists` | watchlist lookups for BGP peers | behaviour |
| NMS `isp` | SIEM `enrich.geo` | GeoIP for ISP gateway AS organisation | utility |
| NMS `selfmon` | SIEM `ingest.pipeline` | `rss_mib()` (process memory reader) | utility |
| NMS `bgp`, `bgp_analysis`, `api/firewalls` | SIEM `paloalto` | the PAN-OS API client (also a vendor adapter for firewalls) | vendor client |
| SIEM `paloalto`, `api/firewalls` | NMS `fortigate` | the FortiGate API client and error types | vendor client |
| SIEM `api/ops` | NMS `bgp`, `fwhealth`, `vpnmon` | the ingest health page shows firewall health / BGP / VPN feed status | UI aggregation |
| SIEM `identity` | NMS `vpnmon` | `_aware`, `_fw` (time and filter helpers) | utility |
| SIEM `assets` | NMS `policy.store` | `to_utc` helper | utility |
| SIEM `api/context` | NMS `drift` | configuration drift in the investigation context | behaviour |

### 2.2 "Shared" hubs that import both products

| Hub | Imports | Problem |
|---|---|---|
| `alerts/engine.py`, `alerts/rules.py` | 7 SIEM + 12 NMS modules | One engine evaluates SIEM detections and NMS fault rules, one `alerts` table, split by rule-key prefix (`products.alert_product`) |
| `worker.py` | 5 SIEM + 14 NMS | One process plan runs both products' loops |
| `reports.py` | 2 SIEM + 8 NMS | One report framework with sections from both products |
| `main.py` | 9 SIEM + 21 NMS routers | One API process |
| `bootstrap.py`, `demo.py`, `devserver.py`, `retention.py` | both | Startup seeding, demo data, development server and retention cover both |
| `api/deps.py`, `api/admin.py` | SIEM `analytics.filters` | The request dependency layer imports SIEM query filters |

### 2.3 Shared data

| Data | Used by SIEM | Used by NMS |
|---|---|---|
| ClickHouse `events` (+ `events_minute`, `events_1m`, `src_hourly`, `traffic_*_hourly`, `policy_usage_hourly`) | everything (security analytics) | VPN tunnels, SD-WAN, BGP events, ISP, policy usage, hardening, network compliance, **network-device syslog** (Cisco / Ruckus, `event_type = netdev`) |
| `firewalls` (+ FortiGate / PAN-OS API tokens) | log-source identity, investigation context | health, policies, IaC, BGP, drift |
| `users`, `audit_log` | yes | yes |
| `alerts`, `alert_rules`, `alert_suppressions` | security alerts | network faults |
| `notification_*`, `report_*`, `assets`, `log_sources`, `retention_*` | yes | yes |
| `incidents` | security incidents (`category='security'`) | WAN "network incidents" are rows of the same table (`category='wan'`, written by `app/wan.py`); switch, wireless and TACACS+ alerts are correlated into security incidents by `incidents.correlate_alerts` (combined deployment only, see REMOVAL_LOG) |
| `wan_settings` | — | NMS settings, now also the BGP critical-prefix list (migration 0037) |

### 2.4 Positives (no work needed)

- **No dead code.** Every backend module has an importer and every frontend page is routed; the only modules without an
  importer are the entry points (`access/__main__`, `flows/__main__`). The removal list is therefore short.
- **Already separated by product at runtime:** API product boundaries, alerts split by rule key, NMS-only services
  (`poller`, `traps`, `flows`, `access`, `ansible`, `tacacs`).
- **NMS-only packages with no SIEM imports:** `access`, `configs`, `flows`, `nms`, `playbooks`, `switches`, `wireless`,
  `iac`, `tacacs`, `netcompliance`.
- **SIEM-only packages with no NMS imports:** `detection`, `enrich`, `ingest`, `incidents`, `mitre`, `response`, `risk`,
  `sigma`, `zeek`, `watchlists`, `analytics` (except their use *by* NMS).

## 3. The central design problem

Much of what NMS shows about firewalls and WAN is derived from **firewall logs**, which the SIEM ingests:
- VPN tunnel status;
- SD-WAN health and failover;
- BGP session events;
- policy hit counts.

The same pipeline also carries network-device syslog for NMS: interface flaps, OSPF / BGP adjacency, configuration
change and wireless events.

So "SIEM keeps the syslog pipeline" alone would leave these NMS pages depending on the SIEM. There are three ways to
separate this:

| Option | How | Independence | Cost |
|---|---|---|---|
| **A. Fan-out at the relay (recommended)** | The `ingress` rsyslog relay (already in front of everything) forwards to both products. Each product runs its own receiver and parser with its own filter. SIEM keeps security categories; NMS keeps network-operational classes (VPN / SD-WAN / BGP / interface / routing / system / config-change, netdev). Each writes its own ClickHouse database with its own retention. The parsers become a shared, business-free library (vendor log formats). | Full: either product runs alone | A second parse of the stream. The NMS receiver pre-filters cheaply on log type before full parsing; needs measurement against production volume (about 700k lines in minutes) |
| B. SIEM exports to NMS | The SIEM pipeline publishes network-operational events to NMS over the optional integration | NMS firewall / WAN pages stop when the SIEM is down | Low |
| C. NMS reads the SIEM store | Today's model, made explicit with a read-only ClickHouse grant | None | None |

## 4. Risks per area

| Area | Risk | Why |
|---|---|---|
| Moving files into `products/…` | Medium | 55k lines, every import path changes. Mechanical but large; git history follows `git mv`; deploy, CI and k8s paths change |
| Two API processes | Low–medium | Already proven with the `access` gateway (same app, product subset) |
| Splitting the alerts engine | Medium | Rule registry and alert tables are shared; the NMS alert pages, incidents and notifications all touch it |
| Separate PostgreSQL databases | **High** | Existing data must be copied, not moved, with verification; there is one Alembic history to split; 116 tables. No destructive step without approval |
| Separate ClickHouse databases | Medium–high | `events` is about the largest data set; NMS-relevant rows would need a filtered copy (or the NMS store starts empty with history kept read-only) |
| Users and SSO | Medium | Two user stores means administering accounts twice unless SSO is added |
| Syslog fan-out | Medium | CPU and memory on the server (earlier syslog / worker pressure); needs a measurement |
| Frontend split | Low–medium | Pages already belong to a product (`OWN`); shared pages must be split per product |

See [MODULE_OWNERSHIP_MATRIX.md](MODULE_OWNERSHIP_MATRIX.md), [TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md) and
[MIGRATION_PLAN.md](MIGRATION_PLAN.md).
