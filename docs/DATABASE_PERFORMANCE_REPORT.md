# Database Performance Report

## 1. Role of each store (verified from code)

| Store | Role | Access layer |
|---|---|---|
| PostgreSQL 16 | Users, RBAC/site scope, inventory (firewalls, switches, WLCs, TACACS, WAN links), configuration, alerts/incidents, NMS state (interfaces, events, poll runs), audit log | SQLAlchemy 2 async + asyncpg; Alembic migrations 0001–0027 |
| ClickHouse 24.8 | High-volume time series: events (+ `events_minute`, `events_1m`, `src_hourly` roll-ups), device/interface metrics, traps, ICMP/WAN samples | `app/db/ch.py`; schema in `app/db/ch_schema.py` |

No new database was added. Redis and a time-series engine were considered and rejected: the bottlenecks found were in how the existing stores are used, not in what they can do.

## 2. Connection management

**Before:** every process used `pool_size=10, max_overflow=20` (30 peak), with no `pool_recycle` or `pool_timeout`.

| Process | Before (peak) | After (peak) |
|---|---|---|
| API (2 uvicorn workers) | 60 | 16 (4 + 4 each) |
| Worker | 30 (fewer than its 20 firewall + 16 switch concurrent polls, each holding a session) | 42, sized as `WORKER_POLL_CONCURRENCY + SWITCH_MAX_CONCURRENT_POLLS + 6` |
| Syslog receiver + 4 parsers | 150 | 16 (8 + 4 × 2) |
| SNMP traps | 30 | 8 |
| Migrate (exits before the others start) | 30 | 8 |
| **Total of long-running processes** | **≈ 270 possible / ≈ 180 typical** | **82**, under PostgreSQL's default of 100 |

- Settings: `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `db_pool_timeout_seconds` (30) and `db_pool_recycle_seconds` (1800). `pool_pre_ping` is kept.
- Tests in `tests/test_modernization.py` assert the defaults, the overrides and that the budget stays under 100.
- **ClickHouse:** one client per process behind a lock was replaced by a pool of `CLICKHOUSE_POOL_SIZE` (default 4) independent clients and a dedicated executor. Peak ClickHouse concurrency is about 4 per process × 8 processes = 32, well under the server's default `max_concurrent_queries` of 100.

## 3. Indexes (migration `0027_query_indexes`)

Each index was chosen from a query actually executed by a hot route. On PostgreSQL every index is built `CONCURRENTLY` (no write lock), and a leftover INVALID build is dropped and rebuilt.

| Index | Serves | Query location |
|---|---|---|
| `alerts (dst_ip)` | `src_ip = x OR dst_ip = x` (investigate, hunt): without it the OR forces a sequential scan | `api/analytics.py`, `api/hunt.py` |
| `alerts (first_seen)` | NMS alert analytics by day | `nms/analytics.py` |
| `alerts (status, last_seen)` | Alert list ordered by recency within a status | `api/alerts.py` |
| `alerts (rule_key varchar_pattern_ops)` | `rule_key LIKE 'switch_%'` / `'wireless_%'` product filters: a plain btree cannot serve prefix LIKE under a non-C collation | `switches/service.py`, `api/wireless.py`, `products.py` |
| `alerts (group_key varchar_pattern_ops)` | `group_key LIKE '<switch id>:%'` | `api/switches.py` |
| `incidents (category, created_at)` | Incident stats and analyst workload by period | `api/soc.py` |
| `switch_events (switch_id, at)`, `(switch_id, kind, at)` | Per-switch event timelines and flap counts | `api/switches.py`, `switches/service.py`, `nms/analytics.py` |
| `switch_poll_runs (switch_id, started_at)` | Polling health and per-switch history | `api/snmp.py`, `switches/service.py` |
| `switch_interfaces (switch_id) WHERE present` | Fleet and per-switch interface lists (partial index on PostgreSQL) | `api/switches.py` |
| `tacacs_health_checks (server_id, at)` | Availability per server | `api/tacacs.py` |
| `wireless_events (ap_id, at)` | AP timelines | `api/wireless.py` |

- **Write cost:** alerts gain 5 indexes and are updated about once per detection per minute, which is moderate. Switch events and poll runs gain 1–2 indexes each.
- **Redundant indexes:** the old single-column `switch_id` indexes on `switch_events` and `switch_poll_runs` are now covered by the composites and could be dropped later. They were left in place because this migration is additive only.
- **Query plans were not captured.** No PostgreSQL server was available in the audit environment; the migration was tested on SQLite and its PostgreSQL DDL rendered offline. After deploying, confirm the plans:

```sql
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM alerts WHERE src_ip = '10.0.0.5' OR dst_ip = '10.0.0.5';
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM alerts WHERE rule_key LIKE 'switch_%' AND status IN ('new','investigating');
EXPLAIN (ANALYZE, BUFFERS) SELECT switch_id, count(*) FROM switch_poll_runs WHERE started_at >= now() - interval '24 hours' AND kind = 'poll' GROUP BY 1;
```

## 4. Query rewrites

| Query | Before | After |
|---|---|---|
| Polling health | Every poll run in the range into Python | One `GROUP BY switch_id` with `SUM(CASE …)` |
| Fleet interfaces | Every present interface + full `Switch` rows into Python, sorted and sliced | `WHERE … ORDER BY … LIMIT/OFFSET` + `count(*)`, with `load_only` on 5 switch columns |
| TACACS availability | One query per server | One `GROUP BY server_id` |
| Latest alert per group | One query per detection | One join against `max(open_seq)` per group |

## 5. Write path and ingestion

- **Event inserts** go in batch-sized chunks. A failed chunk is retried unchanged, separate from new events. The buffer is capped (`SYSLOG_BUFFER_MAX_EVENTS`, default 10 × batch) with backpressure. A chunk ClickHouse keeps rejecting while other chunks insert is spooled to `INGEST_DEADLETTER_DIR` after `INGEST_INSERT_MAX_ATTEMPTS` (3) and can be replayed with `python -m app.ingest.deadletter replay`.
- **Not changed (backlog):**
  - per-interface PostgreSQL `UPDATE` on every poll, about 100k row updates/min at 2,000 switches (TD-03);
  - small per-switch ClickHouse inserts without `async_insert` (TD-03);
  - insert deduplication tokens for retries after timeouts (TD-18).

## 6. ClickHouse schema observations (backlog, not changed)

- `events` uses `PARTITION BY (category, toYYYYMMDD(event_time))`. Thousands of partitions build up at long retention, and a backfill spanning days can exceed `max_partitions_per_insert_block`. That case is now spooled instead of blocking ingestion.
- `event_id` is last in `ORDER BY`, so an event-detail lookup reads every partition. A bloom-filter skip index is proposed (TD-07); materialising it on a large table is heavy I/O and should run off-peak.
- `src_hourly` is ordered by `(src_ip, hour, …)`, but the alert rules filter by `hour` only. A minmax index on `hour` is proposed (TD-19).

## 7. Migration safety

- `0027` is additive and reversible. `tests/test_modernization.py::test_migration_0027_upgrade_downgrade_roundtrip` runs the whole chain on SQLite, then downgrades to 0026 and upgrades again.
- The production PostgreSQL DDL was rendered offline (`alembic upgrade 0026:0027 --sql`) and reviewed. Every statement is `CREATE INDEX CONCURRENTLY`, run outside a transaction.
- No data is changed or deleted.
