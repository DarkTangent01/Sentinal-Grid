# Service dependencies

All services are defined in `docker-compose.yml` (one project on the production host). The deployment column is
`scripts/release.sh`'s strategy for that service.

## Services

| Service | Image (tag variable) | Role | Depends on | Deployment |
|---|---|---|---|---|
| postgres | `postgres:16.15-alpine@sha256` (pinned) | configuration, alerts, incidents, inventory, leases | volume `pgdata` | **infrastructure**: never by a deployment |
| clickhouse | `clickhouse-server:24.8.14.39@sha256` (pinned) | events, metrics, flows, rollups | volume `chdata` | **infrastructure**: never by a deployment |
| migrate | backend (`MIGRATE_TAG`) | Alembic + ClickHouse migrations, seed (one-shot) | postgres, clickhouse | own step, before backend services |
| api ×2 | backend (`API_TAG`) | REST API (both products), single-process containers | postgres, clickhouse, tacacs (AAA tests) | rolling |
| worker | backend (`WORKER_TAG`) | alert engine, retention, jobs, SOC summaries, identity index, enrichment, ICMP | postgres, clickhouse, tacacs | replace |
| poller ×3 | backend (`POLLER_TAG`) | SNMP device polling (leases) | postgres, clickhouse | rolling, one at a time |
| access | backend (`ACCESS_TAG`) | device access gateway (terminal, diagnostics) | postgres | replace |
| ansible | ansible (`ANSIBLE_TAG`) | playbook runner | postgres | replace |
| ingress | ingress (`INGRESS_TAG`) | syslog front end (rsyslog, disk spool), host UDP / TCP 514 | syslog | explicit only |
| syslog | backend (`SYSLOG_TAG`) | parsing, enrichment, writes events | ingress (its input), clickhouse, postgres | replace (ingress buffers) |
| traps | backend (`TRAPS_TAG`) | SNMP trap receiver, host UDP 162 | postgres, clickhouse | replace |
| flows | backend (`FLOWS_TAG`) | NetFlow / IPFIX / sFlow collector, host UDP 2055 / 4739 / 6343 | clickhouse | replace |
| web | web (`WEB_TAG`) | nginx: TLS, proxy to api / access, serves the UI volume; host 80 / 443 | api, access (by DNS name), volume `ui` | edge: only when nginx changes |
| ui-release | web (`UI_TAG`) | one-shot UI publisher (profile `release`) | volume `ui` | `ui` target |
| tacacs | tacacs (`TACACS_TAG`) | TACACS+ server (profile `tacacs`), host TCP 49 | — | explicit only |

## Networks

| Network | Members | Notes |
|---|---|---|
| `backend` (internal) | databases and backend services | no egress |
| `frontend` | web, api, access, ui-release | |
| `ingest` (internal) | ingress ↔ syslog | |
| `syslog_edge` | the ingress's published port | |
| `egress` | services that reach devices / the internet | |
| `aaa` | api / worker ↔ tacacs | |

## Volumes (persistent)

| Volume | Contents |
|---|---|
| `pgdata` | PostgreSQL |
| `chdata` | ClickHouse |
| `ingress_spool` | syslog buffer |
| `deadletter` | rejected event chunks |
| `tacacs_config`, `tacacs_logs` | TACACS+ |
| `ui` | UI releases |

None is removed or recreated by a deployment.

## Coupling that matters for deployments

- **web → api:** nginx resolves `api` every 2 s and balances across every api container (two by default; a new one joins only once healthy and warm), which is what lets the API roll. The web health check goes through the api, so an api outage shows as web unhealthy too.
- **api ↔ worker:** they share no process state, only the database. Either can be deployed alone.
- **pollers:** coordinate only through `switches.lease_until`. Any number of old and new replicas can run together.
- **access:** closes orphaned sessions when it starts. Never run two.
- **syslog ← ingress:** deploy `syslog` freely (the ingress spools). Deploy `ingress` only when its own configuration changes; it holds the host port.
- **migrate → everything backend:** schema changes must be expand-only. The previous version of every service must keep working on the new schema (`app.migrate_check` enforces it).
- **ui ↔ api:** a UI release may call API endpoints that don't exist yet. Deploy `api` (or `backend`) before `ui` when both change; `all` and `auto` already use that order.
