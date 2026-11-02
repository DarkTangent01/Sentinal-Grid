# Project Architecture Audit — Sentinel Grid (SIEM) and Sentinel NMS

- **Date:** 2026-11-02
- **Scope:** the whole repository at commit `f9ca361`, plus every uncommitted change in the working tree. That tree is about 40k backend lines and 50+ frontend pages, and a snapshot is kept on the local branch `checkpoint/pre-modernization-20261102`.
- **Method:** the architecture below was checked against the source code, not taken from the docs. Four parallel read-only reviews (API/DB, NMS polling, ingestion, frontend) were cross-checked before anything was changed.

This audit is one of ten companion documents:

| Document | Contents |
|---|---|
| `CODE_QUALITY_REPORT.md` | Code quality findings |
| `FRONTEND_PERFORMANCE_REPORT.md` | Frontend performance |
| `API_PERFORMANCE_REPORT.md` | API performance |
| `DATABASE_PERFORMANCE_REPORT.md` | Database performance |
| `SECURITY_REVIEW.md` | Security review |
| `PERFORMANCE_BENCHMARKS.md` | Benchmark numbers |
| `TECHNICAL_DEBT_REGISTER.md` | The prioritised backlog |
| `IMPLEMENTATION_CHANGELOG.md` | What was changed |
| `DEPLOYMENT_AND_ROLLBACK_GUIDE.md` | How to deploy and roll back |

## 1. Components (as built)

| Component | Process / container | Source | Role |
|---|---|---|---|
| Web | `web` (nginx 1.27 + static SPA) | `frontend/` | TLS, security headers, `/api` reverse proxy |
| API | `api` (uvicorn × 2 workers, FastAPI) | `backend/app/main.py`, `app/api/*.py` (23 routers) | REST API, auth/RBAC, product (Grid/NMS) and site scoping |
| Worker | `worker` (one asyncio process; firewall polling is sharded) | `app/worker.py` | Firewall API polling, BGP, policy sync, alert rules, retention, ICMP, switch/WLC SNMP polling, NMS service checks, TACACS jobs, IaC executor, TI feeds, notifications |
| Syslog | `syslog` (receiver + up to 4 parser processes) | `app/syslog_server.py`, `app/ingest/*` | Parse/normalise/enrich/dedupe FortiGate, PAN-OS, CEF/generic and Windows events, then ClickHouse |
| Ingress relay | `ingress` (rsyslog, own image) | `deploy/ingress/` | Owns host port 514; spools to disk while `syslog` restarts |
| SNMP traps | `traps` | `app/snmp_traps.py` | v1/v2c/v3 trap receiver |
| TACACS+ | `tacacs` (agent) | `deploy/tacacs/`, `app/tacacs/` | AAA server managed by the SIEM |
| PostgreSQL 16 | `postgres` | `app/db/models.py`, `migrations/` (0001–0027) | Users, inventory, config, alerts/incidents, NMS state, audit log |
| ClickHouse 24.8 | `clickhouse` | `app/db/ch.py`, `app/db/ch_schema.py` | Events, roll-ups, device/interface metrics, traps, WAN/ICMP samples |
| Migrate | `migrate` (runs once, then exits) | `app/migrate.py` | Alembic + ClickHouse schema + seed data |

There is no task queue, Redis, Kubernetes or WebSocket/SSE layer. The UI polls through TanStack Query. That is a reasonable choice at this size, and this audit does not add infrastructure.

## 2. Layering (verified)

- **API layer** (`app/api/*.py`)
  - Request validation uses Pydantic.
  - Auth and RBAC come from the `deps.current_user` / `require_admin` dependencies, with site scoping (`site_allowed`) and product scoping (`app/products.py`).
  - Several routers are large: `tacacs.py` 1,263 lines, `hunt.py` 958, `switches.py` 842, `iac.py` 753. They contain business logic and query building that belong in services (see CODE_QUALITY_REPORT §2).
- **Service layer:** `app/switches/`, `app/wireless/`, `app/nms/`, `app/tacacs/`, `app/iac/`, `app/analytics/`, `app/alerts/`, `app/policy/`, `app/fortigate/`. Most new modules follow a `service.py` / `store.py` split, which is good. Older SIEM routes still query inline.
- **Data access:** SQLAlchemy 2 async ORM (PostgreSQL) and the `ClickHouse` wrapper (`app/db/ch.py`), with server-side parameter binding in production. No raw string SQL takes user input (see SECURITY_REVIEW).
- **Vendor adapters:** each vendor is isolated behind its own module:
  - FortiGate REST: `app/fortigate/client.py`
  - PAN-OS XML: `app/paloalto.py`
  - SNMP: `app/switches/snmp.py` + `collect.py` + the `snmp_profiles.py` registry
  - TACACS: `app/tacacs/client.py`
  - LDAP

  New vendors plug into the SNMP registry without changing the poll engine. The adapter boundary is sound.
- **Background work:** every subsystem runs as an `async` loop inside `worker.py`, ticking every 5–10 s. There is no queue between the scheduler and the pollers (see §4).

## 3. Strengths confirmed in code

- Parameterised ClickHouse SQL, plus an allow-listed query language (`analytics/ql.py`).
- A read-only FortiGate client by design. Firewall writes exist only in IaC, behind two independent switches.
- The SNMP engine is fully asyncio (pysnmp v3arch), batches GETs 20 OIDs per PDU, uses GETBULK walks, and allows one request in flight per device. It has per-device failure isolation and backoff for switches.
- Ingestion is bounded at the receiver: UDP drops are counted, TCP has backpressure, parser queues are bounded, and there is a deduplication LRU.
- Prior security hardening is in place: SSRF guard, session revocation, CSRF, rate limits, security headers.
- 417 automated backend tests and 38 frontend tests at baseline.

## 4. Architectural problems found (ranked)

| # | Problem | Where | Impact | Status |
|---|---|---|---|---|
| A1 | All ClickHouse calls in a process were serialised behind one locked client, and blocking calls shared the default thread pool | `db/ch.py` | One slow hunt or export query blocked every dashboard in that API worker. The worker's inserts queued behind 60 s alert queries | **Fixed**: client pool and dedicated executor |
| A2 | PostgreSQL connection budget of about 180 (6 processes × 30) against `max_connections=100`; the worker needed more than its pool allowed (polls hold sessions during network I/O) | `db/pg.py`, `worker.py` | "too many clients" errors under load, and pool checkout timeouts in the worker | **Fixed**: per-process budget of 82 |
| A3 | Ingestion buffer unbounded while ClickHouse is down; one rejected batch blocked all later events | `ingest/pipeline.py` | Out-of-memory kill of `syslog` (2 GB limit) and loss of every buffered event; ingestion halted permanently on a poison batch | **Fixed**: cap, backpressure, chunking, dead-letter spool |
| A4 | Poll cycles are barriers (`gather` over all due devices): the slowest device sets the cadence for everyone | `worker.py:poll_loop`, `switches/poller.py:run_due`, `icmp.py`, `nms/services.py` | At 2,000 switches the cycle reaches 250 s to 20 min; one dead firewall stalled firewall polling by about 75 s per cycle | **Partly fixed**: firewall backoff, real per-poll start times. Long-lived workers with a queue are in the backlog (TD-01) |
| A5 | DB sessions held across network I/O (switch poll up to 240 s, firewall poll for every HTTP call) | `poller.py:run_due`, `worker.py:poll_loop` | Pool sized to concurrency instead of to real DB work | Mitigated by A2's budget; real fix is TD-02 |
| A6 | Whole-table loads into Python for list and summary endpoints | `api/snmp.py`, `api/switches.py`, `api/tacacs.py`, `switches/service.py`, `nms/analytics.py`, `api/wireless.py`, `api/soc.py` | Memory and latency grow with fleet size (polling-health read about 20 M rows per week of range) | **Fixed for the 3 hottest**; the rest are TD-08 to TD-10 |
| A7 | Single 2.4 MB frontend bundle; global context re-rendered the whole app on every query | `frontend/src/App.tsx`, `lib/context.tsx` | Slow first load; every dashboard refresh redrew every chart about 13 times | **Fixed** |
| A8 | Alert rules evaluate `[now-window, now)` on event time with no stored watermark | `alerts/engine.py` | Late events (after an outage or replay) are never evaluated by any rule | Backlog TD-04 (changes alert semantics; needs a product decision) |
| A9 | ClickHouse `events` partitioned by (category, day), with `event_id` last in the sort key and no skip index | `db/ch_schema.py` | Event-detail lookup scans every partition; many small parts | Backlog TD-07 (needs a table rebuild) |
| A10 | No CI, no request correlation, no metrics endpoint | repository root, `main.py` | Regressions and incidents are hard to detect and trace | **Fixed**: CI workflow, request IDs, `/api/metrics` |

## 5. Dependency direction / cycles

Imports flow api → services → db/models. Cycles are avoided with function-level imports in about 40 places (for example `from ..switches.discovery import ...` inside functions in `worker.py` and `api/*.py`). That works, but it hides the dependency graph. It is listed as TD-16; untangling it is a refactor with no performance benefit, so it was not done in this pass.

## 6. Decisions taken

- **No new infrastructure:** no Redis, no queue broker, no microservices. Every fix uses the existing PostgreSQL, ClickHouse and processes.
- **No breaking API changes:** every response shape is unchanged. The benchmarks confirm identical response sizes for the optimised endpoints.
- **Schema changes are additive only:** migration `0027` adds 12 indexes concurrently, and its downgrade drops exactly those.
