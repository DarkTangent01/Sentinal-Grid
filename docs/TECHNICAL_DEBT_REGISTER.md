# Technical Debt Register — prioritised backlog

**Priority:** P1 means do next (scale or correctness risk), P2 means soon, P3 means opportunistic.
**Effort:** S is ≤ 1 day, M is 2–4 days, L is a week or more.
Every item is open unless marked otherwise.

| ID | P | Effort | Area | Item | Why it matters | Proposed approach | Risk |
|---|---|---|---|---|---|---|---|
| TD-01 | P1 | L | NMS polling | Poll cycles are barriers (`gather` over all due devices) in `worker.py:poll_loop`, `switches/poller.py:run_due`, `icmp.py` and `nms/services.py` | The slowest device sets everyone's cadence; about 250 s per cycle at 2,000 switches on a LAN is an estimate | Long-lived worker tasks fed by a bounded `asyncio.Queue`; `next_due = last_start + interval` with per-device phase jitter; keep the DB lease | Medium (scheduling semantics) |
| TD-02 | P1 | M | NMS polling | DB sessions held across network I/O (switch poll up to 240 s, firewall HTTP polls) | Pool must be sized to concurrency; stale rows | Load, close the session, poll, then open a new session to persist (optimistic version check) | Medium |
| TD-03 | P1 | M | Ingestion of metrics | One PostgreSQL `UPDATE` per interface per poll (`poller.py:478-487`); 2–5 tiny ClickHouse inserts per switch per poll with no `async_insert` | WAL/bloat (about 100k updates/min at 2,000 switches); "too many parts" | Keep hot counters in process memory, write PostgreSQL only on change with bulk `UPDATE … FROM (VALUES …)`; per-table insert buffer or `async_insert=1` | Medium |
| TD-04 | P1 | M | Alerting | Rules evaluate `[now-window, now)` on `event_time` with no stored watermark (`alerts/engine.py`) | Events arriving late (outage, relay or dead-letter replay) are never evaluated | Per-rule stored watermark on `ingest_time` with a late-arrival allowance | Medium: alert counts change, so it needs a product decision |
| TD-05 | P2 | M | Alerting | Incident correlation N+1 (`incidents.py:107-139`): per alert, an incident lookup plus a 2 h peer scan | O(alerts × open alerts) during storms | Load peers once and bucket them by entity; batch-load incidents; recompute members once per incident | Medium (in-batch visibility) |
| TD-06 | P2 | S | Alerting | `notify` skipped when correlation fails after the alerts are committed (`engine.py:985-995`); outbox delivers serially with a 15 s timeout | Lost notifications; one dead webhook stalls background jobs | Enqueue the outbox in the same transaction; deliver with bounded concurrency and a per-channel circuit breaker | Low |
| TD-07 | P2 | S | ClickHouse | `event_id` lookups scan every partition (`analytics/queries.py:427`) | Event detail and context latency grows with retention | `ADD INDEX idx_eid event_id TYPE bloom_filter(0.001) GRANULARITY 1`, then `MATERIALIZE` off-peak; or pass `event_time` from the UI | Low (heavy I/O during materialise) |
| TD-08 | P2 | M | API | Wireless clients (up to 50k rows), `/wireless/aps` full loads (`api/wireless.py`, `wireless/service.py`) | Memory and latency at large WLCs | SQL filter/sort/page + count; `GROUP BY` for overview counts | Low |
| TD-09 | P2 | S | API | NMS alert analytics aggregates 20k alerts + 100k events in Python (`nms/analytics.py:453,476`) | Same | `GROUP BY kind`, `date_trunc('day')`; MTTR via `avg(last_seen-first_seen)` (index added in 0027) | Low |
| TD-10 | P2 | M | API | Switch overview top-15 lists from full loads (`switches/service.py:124-146`); incident stats and workload in Python (`api/soc.py`) | Same | `ORDER BY … LIMIT 15`; SQL aggregates with `FILTER` | Low |
| TD-11 | P3 | L | Code structure | Oversized routers (`api/tacacs.py` 1,263 lines, `hunt.py`, `switches.py`, `iac.py`) | Reviewability, reuse | Move query building into service modules and keep routes thin; one module at a time with existing tests as the safety net | Low |
| TD-12 | P2 | M | Frontend | Alerts and incidents fetch 200 rows every 30 s; switch events 500; `ResultTable` uncapped; no virtualisation | Render cost, payload size | Server-side paging at 50, `React.memo` rows, cap at 500 with "show more", `@tanstack/react-virtual` for big tables | Low |
| TD-13 | P3 | S | Frontend | Remaining per-keystroke inputs on TACACS pages; `Dashboard` `sevTypes` `useMemo` | Request storms on typing | `useDebounced` (already in `components/ui.tsx`) | Low |
| TD-14 | P2 | M | Tooling | No MyPy/Pyright | Type regressions | Start with `pyright --level basic` on `app/` in CI as non-blocking, then tighten | Low |
| TD-15 | P2 | M | Tooling | No ESLint/Prettier, React Testing Library or Playwright; Lighthouse not measured | Render regressions untested; no E2E or Web Vitals numbers | Add ESLint (react-hooks), RTL for the context/Chart render counts, Playwright smoke tests per product, a Lighthouse CI job against `vite preview` | Low |
| TD-16 | P3 | M | Code structure | About 40 function-level imports used to avoid cycles | Hidden dependency graph | Extract shared types/helpers into leaf modules; enforce with `import-linter` | Low |
| TD-17 | P3 | M | API | `/api/events` allows OFFSET up to 5 M with an exact count per page | Slow deep pages | Keyset pagination on `(event_time, event_id)` with a cursor; cap OFFSET | Medium (API contract) |
| TD-18 | P2 | S | Ingestion | Retried inserts after a client timeout can double-insert (roll-ups never dedupe) | Over-counting | Per-chunk `insert_deduplication_token` (stable across retries) | Low |
| TD-19 | P3 | S | ClickHouse | `src_hourly` ordered by `src_ip` but rules filter by `hour` | Full partition scan per rule | `ADD INDEX idx_hour hour TYPE minmax` + `MATERIALIZE`, or rebuild ordered by `(hour, src_ip)` | Low to medium |
| TD-20 | P3 | S | Observability | `/api/metrics` is per process and needs an admin session; no worker, syslog or trap metrics endpoint (only logs and heartbeats) | Hard to scrape; ingestion counters invisible in dashboards | Scrape token; a small metrics HTTP endpoint (127.0.0.1) in worker, syslog and traps exposing the existing counters, queue depth, insert latency and pool waits | Low |
| TD-21 | P3 | M | ClickHouse | `events` partitioned by (category, day); thousands of partitions at long retention | Merge load, partition-limit failures on backfill (now dead-lettered, not blocking) | `PARTITION BY toYYYYMMDD(event_time)` and `ORDER BY (category, toStartOfHour(event_time), firewall_id, …)` via a new table and backfill | High (data migration) |
| TD-22 | P3 | S | NMS | WLC background polls each create their own semaphore, so the global bound leaks | Exceeds `SWITCH_MAX_CONCURRENT_POLLS` | One per-event-loop semaphore shared by `run_due` and background tasks | Low |
| TD-23 | P3 | S | NMS | SNMP PDU budget 60 varbinds for `walk_multi`; Cisco VLAN-context MAC walks every poll | Extra round trips | Raise to about 120 per vendor profile; slow-interval MAC walks | Low to medium (agent PDU limits) |
| TD-24 | P3 | S | Traps | A failed ClickHouse insert drops the trap batch; engine rebuild on inventory change rebinds the socket | Lost traps | Retry or spool like events; incremental USM user updates | Low |
| TD-25 | P3 | S | Ingestion | CEF field split can be quadratic on long space runs; deep JSON recursion only caught after the CPU is spent | CPU on hostile input | Linear split; depth cap before parsing | Low |
| TD-26 | P3 | S | Deployment | Base images pinned by tag, not digest; no image scan in CI | Supply chain | Pin digests; add a Trivy job | Low |
| TD-27 | P3 | S | Ingestion | Shutdown stops parser workers one after another (up to about 100 s) against a 30 s grace period | Buffered events lost on stop | Close TCP sessions first, stop workers in parallel within 20 s, spool unflushed chunks to the dead-letter directory | Low |

**Done in this pass** (details in `IMPLEMENTATION_CHANGELOG.md`):
- ClickHouse client pool;
- PostgreSQL connection budget;
- bounded ingestion with backpressure and dead-letter spool;
- TCP framer robustness;
- 12 query indexes;
- polling-health, fleet-interfaces and TACACS-health SQL aggregation;
- batched alert lookup;
- DNS rule interval tiling;
- firewall poll backoff;
- real per-poll switch timestamps;
- O(log n) threat-intel CIDR lookup;
- bounded trap dedup;
- request IDs, access log and metrics;
- CI;
- frontend code splitting, tree-shaken ECharts, render fixes, request cancellation and debounced searches.
