# Performance remediation plan

Root causes and evidence: [INITIAL_AUDIT.md](INITIAL_AUDIT.md). The fixes are ordered by impact. Each one is the
smallest change that removes its cause, preserves every rule and integration, and has its own regression test.

## Phase 1: isolate SNMP polling (RC-1)

| | |
|---|---|
| Change | `WORKER_ROLES` selects which loops a worker process runs. The default `all` keeps today's behaviour. A new compose service `poller` (same image) runs `WORKER_ROLES=snmp` (switch / WLC polling and discovery); `worker` runs `WORKER_ROLES=core` (everything else). Each process has its own heartbeat file and health check. |
| Why it works | SNMP decoding gets its own core, and alerting, notifications, FortiGate polling and policy sync get theirs. Neither can starve the other. Polls are claimed with a database lease (`switches.lease_until`), so more poller replicas share devices safely when the fleet grows (`docker compose up -d --scale poller=N`). |
| Also | Event-loop lag and per-loop timing are recorded in the heartbeat and logged, so starvation is visible if it returns. |
| Files | `app/worker.py`, `app/config.py`, `docker-compose.yml` |
| Risk / rollback | Low. Remove the `poller` service and unset `WORKER_ROLES`: the worker runs everything again. No data change. |

## Phase 2: rollup-based baselines for `new_country` / `new_port` (RC-2)

| | |
|---|---|
| Change | ClickHouse migration 17 adds `traffic_dims_daily` (per day: allowed traffic's `dst_country`, and `(src_ip, dst_port)` for external destinations), filled by a materialised view and backfilled one day at a time. The baselines read the rollup for whole days and raw events for the partial first and last day and the creation seam, so the result stays exact (same pattern as migration 16). `_learning_ok` reads the earliest day from `events_minute` instead of scanning every traffic row. |
| Files | `app/db/ch_schema.py`, `app/alerts/engine.py` |
| Risk / rollback | Additive tables only, no change to `events`. Rollback: the old query text is kept behind `ALERT_BASELINE_FROM_ROLLUP=false`. The tables can stay or be dropped later; nothing else depends on them. |

## Phase 3: incremental identity baseline (RC-3)

| | |
|---|---|
| Change | The 30-day baseline is built from **per-day** aggregates (countries, /24 networks, devices, sources, local-hour histogram per user, successful logins only). Each full day is computed once and cached in memory; only the partial edge days are queried each pass. Each per-day query is small, so no sort over 30 days, and the 200k cap now applies per day, which removes the "newest events dropped" bug. |
| Files | `app/identity.py`, `app/alerts/engine.py` |
| Risk / rollback | Detection semantics unchanged: a test compares the cached baseline with the old full baseline. A worker restart re-warms the cache (≈ 30 small queries once). |

## Phase 4: ClickHouse per-query protection (RC-5)

| | |
|---|---|
| Change | Every query from the app carries `max_memory_usage` (default 2 GiB; `CLICKHOUSE_QUERY_MAX_MEMORY`), `max_bytes_before_external_group_by` / `_sort` (half of it: large aggregations spill to disk instead of failing) and the existing 60 s `max_execution_time`. One query can no longer take the server budget that inserts need. |
| Files | `app/db/ch.py`, `app/config.py` |
| Risk / rollback | A query needing more than 2 GiB would fail; after Phases 2–3 none comes close (largest measured: 209 MiB). Tunable or 0 to disable. |

## Phase 5: bounded syslog memory (RC-4)

| | |
|---|---|
| Change | Insert buffer cap `3 × batch` (was `10 ×`). It is safe because TCP and the rsyslog relay push back, and the relay queues on disk: no loss. GeoIP cache 50k, dedupe window 50k (both configurable). After a large flush the parser runs `gc` and `malloc_trim(0)` so a peak does not stay resident. Each parser reports its RSS with its counters. |
| Expected | ≈ 6 × 300 MiB + receiver ≈ 2 GiB worst case (was ≈ 3.2 GiB). |
| Files | `app/ingest/pipeline.py`, `app/enrich/geo.py`, `app/syslog_server.py`, `app/config.py` |
| Risk / rollback | All values are settings; the previous ones restore today's behaviour. |

## Phase 6: staleness alert correctness (RC-7)

| | |
|---|---|
| Change | The staleness check uses the poller's effective interval (`max(30, configured)`). The threshold is `stale_intervals × interval + the device's poll budget` (switch / WLC timeout) `+ grace`, from the rule's parameters, and the message reports the configured interval. |
| Files | `app/switches/alerts.py` |

## Phase 7: resources (RC-8), after Phases 1–5 are measured

Proposed limits within 15 GiB:

| Service | Limit |
|---|---|
| ClickHouse | 7 GiB |
| syslog | 2.5 GiB |
| worker | 1 GiB |
| poller | 1 GiB |
| postgres | 2 GiB |
| api | 1 GiB |
| traps, tacacs | 0.5 GiB each |
| ingress | 0.5 GiB |
| web | 0.25 GiB |

Total ≈ 16.25 GiB of limits against ≈ 12 GiB expected use. These are applied only after production measurements
confirm the new usage; they are documented in DEPLOYMENT_GUIDE.md, not changed blindly.

## Testing

Unit and regression tests for every phase. Load tests:
- **SNMP scheduler:** 100 / 500 / 1,000 simulated devices; one unreachable; one slow; auth failures. Bounded
  concurrency, and no device waits on another.
- **Syslog:** sink bursts and a ClickHouse outage: bounded buffer, backpressure, nothing dropped silently.
- **Engines:** identity and the rollup baselines against the old results.
- **Full backend suite.**

## Deployment order

1. Code and migration 17 (`migrate` runs it; additive).
2. `poller` service with `WORKER_ROLES` on both workers.
3. Measure for 24 h.
4. Resource limits.

Details and rollback: DEPLOYMENT_GUIDE.md.
