# Implementation Changelog — modernization pass (2026-11-02)

- **Checkpoint:** the complete pre-change working tree, including all previously uncommitted work, is on the local branch `checkpoint/pre-modernization-20261102` (commit `c466488`). `main` and the working tree were not reset or rewritten, and nothing was pushed.
- **Scope:** every change is backward compatible at the API level. The only schema change is additive (migration `0027`).

## Backend

| Area | Files | Change | Test |
|---|---|---|---|
| PostgreSQL pools | `app/config.py`, `app/db/pg.py`, `app/worker.py`, `app/syslog_server.py` | `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` (4/4), `pool_timeout` 30 s, `pool_recycle` 30 min. The worker sizes its own pool from both poll concurrency limits; syslog parsers use 1+1. Peak budget about 180 → 82 | `test_pool_*`, `test_connection_budget_stays_under_postgres_default` |
| ClickHouse client | `app/db/ch.py`, `app/config.py` | One locked client replaced by a pool of `CLICKHOUSE_POOL_SIZE` (4) clients and a dedicated executor. Connects once at startup as before. Embedded (chdb) mode unchanged | `test_clickhouse_queries_run_concurrently_up_to_pool_size` |
| Ingestion buffer | `app/ingest/pipeline.py`, `app/syslog_server.py`, `app/config.py` | Chunked inserts; failed chunks kept unchanged in a retry list; buffer cap (`SYSLOG_BUFFER_MAX_EVENTS`) with backpressure (TCP sessions and parser workers pause); inline-UDP drops counted (`dropped_buffer_full`); poison chunks dead-lettered after `INGEST_INSERT_MAX_ATTEMPTS` (3); new counters `insert_failures` and `dead_lettered` | `test_clickhouse_outage_keeps_events_in_order_and_bounded`, `test_poison_chunk_is_dead_lettered_and_replayable` |
| Dead-letter spool | `app/ingest/deadletter.py` (new), `backend/Dockerfile`, `docker-compose.yml` | JSON-lines spool with atomic writes and `python -m app.ingest.deadletter list\|replay`. Named volume `deadletter` on `syslog` and `worker`. A spool that can't be written keeps the chunk buffered | same |
| TCP framing | `app/syslog_server.py` (`Framer`) | Oversized frames and lines are skipped and counted (`oversized`); lines starting with a digit are no longer misread as octet counts; the shared relay session stays open | `tests/test_ingress_relay.py`: the old test that asserted a raise was replaced by `test_framer_skips_oversized_frames_and_keeps_the_session` and `test_framer_newline_line_starting_with_digit` |
| Indexes | `app/db/models.py`, `migrations/versions/0027_query_indexes.py` (new) | 12 indexes (see `DATABASE_PERFORMANCE_REPORT.md` §3), built `CONCURRENTLY` on PostgreSQL | `test_migration_0027_upgrade_downgrade_roundtrip` |
| Polling health | `app/api/snmp.py` | SQL `GROUP BY` instead of loading all poll runs | `test_polling_health_aggregates_runs_in_sql` |
| Fleet interfaces | `app/api/switches.py` | SQL filter, sort, count and page; `load_only`; stable tie-breaker | `test_fleet_interfaces_sort_filter_page_in_sql` (includes site scope) |
| TACACS health | `app/api/tacacs.py` | One aggregate instead of one query per server | `test_tacacs_health_availability_aggregate` |
| Alert upsert | `app/alerts/engine.py` | `_latest_alerts()`: one query per rule; an in-run map handles repeated groups | `test_upsert_detections_batches_lookup_and_handles_repeat_groups` |
| Rule cadence | `app/alerts/rules.py` | `dns_spike` and `new_domain` get `interval_minutes: 10`, equal to their 10-minute window, so coverage still tiles. Existing installs get the key at the next seed without overwriting tuned params | existing alert tests |
| Firewall polling | `app/worker.py` | `firewall_backoff()`: unreachable and auth-failing firewalls back off like switches (2 failures, then doubling to 15 min) | `test_firewall_backoff_schedule` |
| Switch polling | `app/switches/poller.py` | Each poll is stamped with its real start time, not the batch claim time (fixes rate skew; de-synchronises the fleet) | `test_queued_switch_poll_uses_its_own_start_time` |
| Threat intel | `app/enrich/ti.py` | CIDR blocks flattened into non-overlapping segments (most specific wins); one binary search per lookup | `test_ti_cidr_lookup_matches_most_specific_block_bruteforce` |
| SNMP traps | `app/snmp_traps.py` | Hard bound on the dedup map (`DEDUP_MAX_KEYS`); queue overflow counted as `dropped_queue_full` | `test_trap_dedup_map_stays_bounded_under_unique_key_storm` |
| Observability | `app/observability.py` (new), `app/main.py`, `app/logging_setup.py`, `app/products.py` | `X-Request-ID` (validated or generated), request ID on every log line, structured access log by route template, admin-only `/api/metrics` (Prometheus text: requests, latency histogram, uptime, DB pool gauges) | `test_request_id_access_log_and_metrics` |
| CI | `.github/workflows/ci.yml` (new) | ruff, pytest, pip-audit; typecheck, vitest, build, runtime npm audit; `compose config` and image builds | — (runs on GitHub) |
| Benchmark | `backend/tools/bench_api.py` (new) | Synthetic-data latency harness | — |
| Config | `.env.example` | Documents the new settings | — |

## Frontend

| Area | Files | Change | Test |
|---|---|---|---|
| Code splitting | `src/App.tsx` | 52 pages through `React.lazy` + one `<Suspense>` | build output: 58 chunks, 83 KB gzip entry |
| ECharts | `src/lib/echarts.ts` (new), `src/components/Chart.tsx`, `src/components/WorldMap.tsx` | `echarts/core` with only the series and components in use | typecheck + build |
| Re-renders | `src/lib/context.tsx`, `src/components/Layout.tsx` | Memoised context value; `markUpdated` removed; `useLastUpdated()` reads the query cache in a leaf component | typecheck (no render test: RTL not installed, TD-15) |
| Chart redraws | `src/components/charts.tsx`, `src/components/Chart.tsx` | Memo keyed on series content; no duplicate mount draw | typecheck |
| Cancellation | `src/lib/api.ts`, `src/lib/context.tsx`, `src/pages/switches/SwitchDetail.tsx` | `signal` forwarded to `fetch` | `src/lib/api.test.ts` |
| Debounce | `src/pages/switches/SwitchDetail.tsx` | Interface and MAC searches debounced at 300 ms | — |
| Duplicate fetch | `src/components/Layout.tsx`, `src/pages/Firewalls.tsx` | One `["firewalls"]` key | — |
| Polling | `src/pages/tacacs/Studio.tsx` | Adaptive 3 s / 30 s job polling | — |

## Verification run

- Backend: **434 passed**, 1 live test deselected.
- Ruff: 44 findings, the same as before this pass (none new).
- Frontend: 39/39 tests, `tsc` clean, production build OK.
- Benchmarks: see `PERFORMANCE_BENCHMARKS.md`.
- **Not run:** Docker image builds, a PostgreSQL migration against a real server (DDL rendered offline), a load test and Lighthouse.
