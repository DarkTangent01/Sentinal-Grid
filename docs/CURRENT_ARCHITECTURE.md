# Current architecture (as built), 2026-11-02

This page is checked against the source, not the earlier design documents. Deeper detail: [ARCHITECTURE.md](ARCHITECTURE.md),
[PROJECT_ARCHITECTURE_AUDIT.md](PROJECT_ARCHITECTURE_AUDIT.md), [PRODUCTS.md](PRODUCTS.md).

## Backend

| Item | Actual |
|---|---|
| Language / runtime | Python 3.12 |
| Framework | FastAPI. App factory `backend/app/main.py:create_app`; uvicorn runs 2 workers in the `api` container |
| API layout | 22 router modules in `app/api/*`; prefixes are `/api/...` with `/api/v1/policies` the only versioned one. Product access (Grid / NMS) is enforced per prefix in `app/products.py` |
| Business logic | Domain modules (`app/incidents.py`, `notify.py`, `wan.py`, `bgp.py`, …) and packages (`alerts/`, `analytics/`, `ingest/`, `enrich/`, `policy/`, `switches/`, `wireless/`, `nms/`, `tacacs/`, `iac/`) |
| Relational DB | PostgreSQL 16 through SQLAlchemy 2 async (asyncpg) with Alembic migrations (`backend/migrations/versions`, 0001-0027). SQLite + aiosqlite in tests / dev |
| Event / time-series store | ClickHouse 24.8 (`clickhouse-connect` HTTP pool; embedded chdb in tests). Versioned migrations in `app/db/ch_schema.py` (1-15) |
| Background processing | No task queue: long-running asyncio loops in `app/worker.py` (firewall polling, policy sync, alert evaluation, retention, TI feeds, reports, ICMP, SNMP, service checks, TACACS+, IaC executor). Separate processes: `syslog_server.py` (receiver + parser workers), `snmp_traps.py` |
| Message broker | None. Syslog is relayed by an rsyslog `ingress` container with a disk queue; the `syslog` service buffers in memory with backpressure, retries and a disk dead-letter spool (`app/ingest/deadletter.py`) |
| Logging | JSON logs (`app/logging_setup.py`) with request IDs (`app/observability.py`) |
| Authentication | Local accounts (Argon2), signed session cookie + CSRF token, lockout, session versioning (`app/api/auth.py`, `app/security.py`) |
| Authorization | Role admin / analyst, product access grid / nms, NMS site scope (`users.sites`), IaC roles, TACACS+ roles |
| Network integrations | FortiGate REST (GET; IaC writes are opt-in), FortiGate / Palo Alto / Windows / CEF / plain syslog, SNMP v2c/v3 polling and traps (Cisco, Fortinet, Juniper, Ruckus, generic), Catalyst 9800 wireless, ICMP probing, TACACS+ (tac_plus-ng), TI feeds over HTTPS, Claude API (optional) |

## Frontend

| Item | Actual |
|---|---|
| Language | TypeScript 5 (strict), React 18, Vite 6 |
| UI | Tailwind CSS with an in-house component kit (`src/components/ui.tsx`), light and dark themes |
| Routing | React Router 6, 52 lazily loaded pages (`src/App.tsx`) |
| State | TanStack Query for server state, React context for filters / user (`src/lib/context.tsx`) |
| API client | `src/lib/api.ts` (fetch, CSRF header, abort signals) |
| Auth flow | Cookie session from `/api/auth/login`; `/api/auth/me` drives product access and navigation (`src/lib/products.ts`) |
| Charts | ECharts core build (`src/lib/echarts.ts`), world map, time / bar / donut charts |
| Dashboards | Grid dashboard, NMS dashboard, module overviews (WAN, wireless, RF, switches, SNMP, analytics) |

## Infrastructure

| Item | Actual |
|---|---|
| Containers | `docker-compose.yml`: postgres, clickhouse, migrate, api, worker, ingress (rsyslog), syslog, traps, web (nginx), tacacs (opt-in profile) |
| Reverse proxy | nginx in `web`: TLS, SPA, `/api` proxy |
| Monitoring | `/api/health`, `/api/ready`, admin `/api/metrics` (Prometheus text), heartbeat-file health checks, in-app health pages |
| Configuration | `.env` (documented in `.env.example`), pydantic settings in `app/config.py` |
| CI | `.github/workflows/ci.yml`: ruff, pytest, pip-audit; tsc, vitest, build, npm audit; compose config and image builds |
| Deployment | `scripts/deploy.sh` (rsync + compose build + up), `backup.sh`, `restore.sh`; production host runs every service above except `tacacs` |

## Event data path (Grid)

```
FortiGate / Palo Alto / Windows / CEF / syslog ──514──▶ ingress (rsyslog, disk queue) ──▶ syslog (receiver)
      ──▶ parser processes: source match → vendor parser → normalize → enrich (TI, geo, assets) → dedupe (event_id)
      ──▶ batched ClickHouse insert (retry → dead-letter) ──▶ events + roll-ups
worker: alert rules (ClickHouse queries every ALERT_INTERVAL_SECONDS) → alerts (PostgreSQL) → incidents → notifications / automation
```

The canonical event model is the ClickHouse `events` table (category, event_type / subtype, src / dst IP and port,
protocol, interfaces, policy, action, app, hostname, URL, bytes / packets, NAT, DNS fields, threat, user, msg, raw).
It is FortiGate-shaped but vendor neutral: every parser maps into it through `app/ingest/normalize.py`.
