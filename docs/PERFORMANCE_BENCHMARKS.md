# Performance Benchmarks (before / after)

Every number below was measured. Nothing is extrapolated except where explicitly marked "estimate".

## 1. Test conditions

| Item | Value |
|---|---|
| Hardware | Apple M3, 8 GB RAM, macOS |
| Python / Node | CPython 3.12.12 / Node 22.12.0 |
| Backend data stores | SQLite (aiosqlite) + embedded ClickHouse (chdb 3.1.2), in-process ASGI via `httpx.ASGITransport`, no network |
| "Before" code | `git archive checkpoint/pre-modernization-20261102 backend`, the working tree before this pass |
| "After" code | the current working tree |
| Data | **Synthetic, not production data:** 300 switches × 48 interfaces (14,400 interfaces), 1 poll run per switch per minute for 24 h (432,000 rows), 20 TACACS servers × 1,440 health checks |
| Method | 31 requests per endpoint; the first is discarded as warm-up; p50 and p95 over 30 |
| Harness | `backend/tools/bench_api.py` (run from `backend/`; for "before", run it from an exported tree: `git archive checkpoint/pre-modernization-20261102 backend \| tar -x -C /tmp/before`) |

**Caveat:** SQLite is single-file and in-process. Absolute numbers on PostgreSQL over a network will differ. The relative gain comes from moving rows out of Python and into SQL, which holds on PostgreSQL as well.

## 2. API latency

| Endpoint | p50 before | p95 before | p50 after | p95 after | Response bytes (before = after) |
|---|---|---|---|---|---|
| `GET /api/snmp/polling-health?range=24h` | 991.9 ms | 1,031.8 ms | 178.8 ms | 188.7 ms | 130,873 |
| `GET /api/switches/interfaces?sort=util&limit=100` | 201.4 ms | 251.6 ms | 16.9 ms | 21.4 ms | 49,819 |
| `GET /api/switches/interfaces?errors_only=true&sort=errors` | 199.9 ms | 250.6 ms | 17.4 ms | 21.9 ms | 49,714 |
| `GET /api/tacacs/health` | 245.0 ms | 251.7 ms | 10.1 ms | 10.8 ms | 12,234 |

Peak resident memory for the whole benchmark process was 476 MB before and 474 MB after; seeding dominates both.

## 3. ClickHouse concurrency (per process)

| | Before | After |
|---|---|---|
| Concurrent requests per process | 1 (global lock) | `CLICKHOUSE_POOL_SIZE` (4) |
| 8 × 200 ms queries (fake client, `test_clickhouse_queries_run_concurrently_up_to_pool_size`) | 1.6 s, serialised by construction | under 0.75 s (asserted), peak concurrency 4, 4 clients reused |

## 4. Threat-intel CIDR lookup (per event, twice)

Feed of one /8 plus 50,000 /24s; 20,000 lookups.

| | Build | Per lookup | Lookups/s on one core |
|---|---|---|---|
| Before | 163 ms | 1,024 µs | about 980 (about 490 events/s with 2 lookups per event) |
| After | 218 ms | 1.5 µs | about 660,000 |

## 5. Frontend bundle (production build)

| | Before | After |
|---|---|---|
| Entry JS (first load) | 2,388 KB / 692 KB gzip | 264 KB / 83 KB gzip |
| Total JS | 2,388 KB | 2,096 KB |
| Chunks | 1 | 58 |

Lighthouse, LCP, INP and CLS were **not measured** (no runner available); see `FRONTEND_PERFORMANCE_REPORT.md` §5.

## 6. Test suite

| | Before | After |
|---|---|---|
| Backend `pytest -m "not live"` | 417 passed, 1 deselected, 119.7 s wall (123 s with `time`), 401 MB RSS | **434 passed**, 1 deselected, 105.6 s, 485 MB RSS |
| `ruff check app tests migrations` | 44 findings (all pre-existing) | 44 findings (no new ones) |
| Frontend `vitest` | 38 passed | 39 passed |
| `tsc -b --noEmit` | clean | clean |

## 7. Connection budget (calculated from configuration, not measured)

PostgreSQL peak connections across long-running processes: **about 180 → 82**, against `max_connections=100`. See `DATABASE_PERFORMANCE_REPORT.md` §2.

## 8. Not benchmarked (and why)

| Item | Reason |
|---|---|
| SNMP polling cycle time at fleet scale | Needs real or simulated SNMP agents at scale. The NMS review's estimate (2,000 switches at 16 slots: about 250 s per cycle on a LAN) is an **estimate** and is unchanged by this pass apart from firewall backoff and timestamps (TD-01) |
| Ingestion throughput (events/s) end to end | The TI lookup gain (§4) removes a per-event cost; end-to-end parser throughput was not re-measured |
| PostgreSQL query plans | No PostgreSQL server available; see `DATABASE_PERFORMANCE_REPORT.md` §3 for the `EXPLAIN` commands to run after deploying |
| Load test (requests/s, error rate under concurrency) | Not run; needs a staging stack with real PostgreSQL and ClickHouse |
