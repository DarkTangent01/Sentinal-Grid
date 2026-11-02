# API Performance Report

- **Stack (verified):** FastAPI 0.140 / Starlette 1.3 on uvicorn (2 workers per API container), SQLAlchemy 2 async (asyncpg on PostgreSQL 16) and clickhouse-connect.
- **Measurement:** latency was measured in-process with the same harness and synthetic dataset against the pre-change code (exported from the checkpoint branch) and the current code. Method and numbers are in `PERFORMANCE_BENCHMARKS.md`.

## 1. Endpoint findings and results

| Endpoint | Problem (before) | Root cause | Fix | p95 before → after |
|---|---|---|---|---|
| `GET /api/snmp/polling-health` | Loaded every `SwitchPollRun` row in the range into Python: about 432k rows/day at 300 switches, about 20 M rows/week at 2,000 | Aggregation in Python | One SQL `GROUP BY switch_id` with conditional sums (polls, ok, timeouts, auth, avg/max duration); same response | **1,032 → 189 ms** |
| `GET /api/switches/interfaces` (sort=util) | Loaded every present interface of every switch plus full `Switch` rows (wide JSON), sorted in Python, sliced one page | Paging in Python | Filters, errors-only, sort, count and `LIMIT/OFFSET` in SQL; `load_only` of 5 switch columns; a stable `(switch_id, ifindex)` tie-breaker (pages no longer reorder) | **252 → 21 ms** |
| `GET /api/switches/interfaces` (errors_only) | Same, plus a Python filter | Same | `WHERE errors > 0` in SQL | **251 → 22 ms** |
| `GET /api/tacacs/health` | One query per server loading every 24 h health row | N+1 | One aggregate query | **252 → 11 ms** |
| All ClickHouse-backed endpoints (dashboards, events, hunts, NMS metrics) | Serialised behind one client lock per process; a 60 s hunt or export blocked every dashboard in that API worker | Single `threading.Lock` around one client | Pool of `CLICKHOUSE_POOL_SIZE` (default 4) independent clients and a dedicated thread pool | 8 concurrent 200 ms queries: 1.6 s serialised → under 0.75 s (test asserts peak concurrency 4) |
| Alert evaluation (worker) | Up to 200 `SELECT … ORDER BY open_seq DESC LIMIT 1` per rule per minute | Query inside the loop | One grouped query per rule; an in-run map keeps a repeated group consistent | 51 SELECTs → 1 in the test |

## 2. Cross-cutting changes

- **Request IDs:** every response carries `X-Request-ID`. A caller's ID is reused only if it matches `[A-Za-z0-9._-]{8,64}`, so log injection is not possible. 500 responses include the ID, and every log line written during the request carries it.
- **Access log:** one structured line per request, with method, *route template*, status and duration. The raw path and query string are never logged. Container health checks are excluded.
- **Metrics:** `GET /api/metrics` (administrators only) in Prometheus text format reports:
  - request counts by route and status class;
  - a latency histogram;
  - uptime;
  - DB pool gauges (size, checked out, overflow).

  Values are per process: each uvicorn worker reports its own, so a scraper sees one worker per request (see the deployment guide).
- **Connection pools:** PostgreSQL pools are sized per process. The budget falls from 180 to 82 against `max_connections=100`, and `pool_recycle` / `pool_timeout` are now set.

## 3. Response shape and compatibility

- No route, parameter or response field changed. The benchmark's response byte counts are identical before and after.
- One intended behaviour change: `/api/switches/interfaces` now breaks ties by `(switch_id, ifindex)`, so the order of rows with equal utilisation is deterministic between pages.

## 4. Not done (backlog)

| Item | Why not now | Ref |
|---|---|---|
| Wireless client list (up to 50k rows in Python), NMS alert analytics (20k alerts + 100k events in Python), switch overview top-15 lists, incident stats | Same SQL rewrite pattern; each needs its own test fixtures | TD-08, TD-09, TD-10 |
| Event-detail lookup by `event_id` scans every ClickHouse partition | Needs a ClickHouse skip index plus `MATERIALIZE` (heavy I/O) or an API change to pass `event_time` | TD-07 |
| Deep `OFFSET` paging on `/api/events` (up to 5 M) | Keyset pagination changes the API contract | TD-17 |
| ETags / conditional requests | Most responses are user- and site-scoped and refresh every 30–60 s; the gain is small without a shared cache | — |
| Response compression | Done by nginx in front (check `gzip on` for `application/json` in `nginx.conf`); not added in the app | — |
