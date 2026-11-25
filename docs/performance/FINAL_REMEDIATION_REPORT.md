# Performance remediation: final report (2026-11-10)

Status: **deployed to production on 2026-11-10 / 11**, in three rounds. Each round's measurements found the next
cause (RC-9 to RC-12 below). Production before / after numbers are under "Before / after". Evidence:
[INITIAL_AUDIT.md](INITIAL_AUDIT.md).
Plan: [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md).

## Confirmed root causes

| # | Root cause | Evidence |
|---|---|---|
| RC-1 | SNMP decoding (pure-Python `pyasn1` / `pysnmp`) saturated the worker's single event loop, which also runs alerting, notifications, FortiGate polling, policy sync and NMS checks | py-spy: 75% of worker CPU in pyasn1 + pysnmp, 0% idle. Alert rules cost 96 s alone, but the pass took 600–1,900 s. The WLC waited ≈ 0.3 s per request on the LAN. Every switch averaged ≈ 66 s |
| RC-2 | `new_country` / `new_port` rebuilt 30-day baselines from raw traffic every pass | 1.28 billion and 579 million rows per run, 32.5 s + 29.2 s |
| RC-3 | `identity_unusual_login` loaded 30 days of auth events (sorted, about 20 regexes per row) into Python every pass; its 200k limit dropped the newest events | the query that hit 6.41 / 6.40 GiB |
| RC-4 | Syslog memory at the limit by configuration: 6 × (≈ 273 MiB state + up to ≈ 230 MiB buffer at 10 × batch), peaks never returned to the OS | per-component measurement on production data |
| RC-5 | No per-query ClickHouse limits: one heavy query could take the server's 6.4 GiB, failing concurrent inserts | `max_memory_usage = 0`; code 241 × 3 in 24 h, including a syslog insert |
| RC-6 | WLC wireless tables need about 2,500 GETBULK requests per full poll (device's 1,500-byte PDU); slow mainly because of RC-1 | per-group timings 25–245 s |
| RC-7 | Staleness alert used `max(60, interval)`: 30 s devices reported as 60 s; threshold blind to the poll budget | `switches/alerts.py` |
| RC-8 | Container memory limits (17.25 GiB) exceed host RAM (15 GiB) | compose + `free` |
| RC-9 | *Found after the first deploy.* Incident correlation reloaded every member alert of an incident for each newly correlated alert (one incident had 22,470 alerts), all through SQLAlchemy ORM + JSON decoding. That kept `worker` at 98% after the SNMP split | py-spy on the production worker: SQLAlchemy loading + `json` decoding under `correlate_alerts` |
| RC-10 | *Found after the first deploy.* One `poller` process saturated a core with pyasn1 decoding for 13 devices, and `claim()` leased every due device to whichever replica woke first | `docker stats` 100% on the poller; extra replicas idle |
| RC-11 | *Found after the second deploy.* The WLC's wireless groups were walked one after another, so a poll took their sum (≈ 257 s of the 272 s: wireless_client 107.5 s, rf_neighbors 77.8 s, radio_rf 26.2 s, radio_meta 20.6 s), and every metric on the controller, including the quick ones, refreshed only every ≈ 5 minutes | `switch_poll_runs.groups` per-group durations |
| RC-12 | *Found after the third deploy.* A poller stopped mid-poll left that device leased for the full budget (WLC: 900 s + 60 s), so after each deploy the WLC (and any device in flight) went unpolled for up to ≈ 16 minutes and showed stale data while every other device was fresh | `switches.lease_until` 07:11:59 on the WLC, 10 minutes after the pollers restarted; no poll run in between |
| RC-13 | *Found after RC-11 was deployed.* The client / RF tables are CPU-bound to decode; walking them concurrently on one poller made each walk slower (clients 96 → 196–216 s, radio RF 26 → 165–189 s) without shortening the poll. The controller's quick metrics were only collected between these 4-minute polls, so they were 4–6 minutes old | `switch_poll_runs.groups`, poller-2 at 88% CPU |

## Code changes

| Area | Change | Files |
|---|---|---|
| RC-1 | `WORKER_ROLES` (`all` default / `core` / `snmp`) with a testable `loop_plan()`; new compose service `poller`; heartbeat from the SNMP loop; event-loop lag monitor (p95 / max every minute, warning when starved) | `app/worker.py`, `docker-compose.yml` |
| RC-2 | Migration 17: hourly rollups `traffic_country_hourly`, `traffic_port_hourly` (views + day-by-day backfill, generic `_rollup_creator`). Baselines read whole hours from the rollups and the partial edge hours and creation seam from raw events, so the results stay exact. `_learning_ok` reads `events_minute`. Fallback switch `ALERT_BASELINE_FROM_ROLLUP` | `app/db/ch_schema.py`, `app/alerts/engine.py`, `app/config.py` |
| RC-3 | `cached_baseline()`: per-day baselines, closed days cached, only edge days queried; 200k limit now per day | `app/identity.py`, `app/alerts/engine.py` |
| RC-4 | Buffer cap 3 × batch; dedupe window / GeoIP cache 50k (settings); `release_memory()` (gc + `malloc_trim`) after a drained backlog; `rss_mib` in parser counters | `app/ingest/pipeline.py`, `app/enrich/geo.py`, `app/config.py` |
| RC-5 | `query_limits()`: `max_memory_usage` 2 GiB per query, spill to disk at 1 GiB for GROUP BY / ORDER BY, 60 s; all configurable | `app/db/ch.py`, `app/config.py` |
| RC-7 | `poll_interval()` = the poller's interval; `stale_after()` = intervals × interval + poll budget + grace (rule parameters); message states the configured interval | `app/switches/alerts.py` |
| RC-9 | `compute_from_db()`: an incident's summary from one grouped SQL query instead of loading its alerts; `correlate_alerts` loads the open unassigned alerts once per pass and recomputes each touched incident once | `app/incidents.py` |
| RC-10 | `poller` service with `replicas: ${POLLER_REPLICAS:-1}` (production: 3); `claim(limit=free slots)` and a refilling background pool, so replicas share the fleet | `app/switches/poller.py`, `docker-compose.yml` |
| RC-11 | The four large wireless groups are walked concurrently (`SWITCH_WIRELESS_GROUP_CONCURRENCY`, default 4) after the groups they depend on; concurrent SNMPv3 walks on one client verified to return the same rows as sequential ones. Intervals: wireless_client 120 → 300 s, wireless_rf_neighbors 300 → 900 s | `app/switches/poller.py`, `app/switches/registry.py` |
| RC-13 | Two jobs per Cisco controller: the quick poll (`lane="fast"`) skips the client / RF tables, and `poll_wireless()` walks them under its own lease (`wireless_lease_until`, migration 0028), possibly on another poller. The wireless job takes radio channels from the store, writes only its groups' state, capabilities and wireless inventory, and never touches reachability, backoff or `last_success_at`. Both jobs lock the device row and re-read it before writing, so neither overwrites the other. Switch `SWITCH_WLC_SPLIT_WIRELESS` (default on) | `app/switches/poller.py`, `app/db/models.py`, `migrations/versions/0028_wireless_lease.py`, `app/config.py` |
| RC-12 | `release_on_shutdown()`: on SIGTERM a poller cancels its in-flight polls and clears their leases, so another replica polls those devices immediately | `app/switches/poller.py`, `app/worker.py` |
| Observability | Per-rule durations: `_slowest` (top 5) in every alert-pass log line; event-loop lag in worker and poller logs; parser RSS in syslog counters | `app/alerts/engine.py`, `app/worker.py`, `app/ingest/pipeline.py` |

**Database changes:** ClickHouse migration 17 only (additive tables and views). No PostgreSQL schema change. Nothing
deleted or rewritten.

**Docker changes:** service `poller`; `WORKER_ROLES` on `worker`. Memory limits deliberately unchanged until they
are re-measured (Phase 7).

## Before / after

**Production, before** (measured 2026-11-10):
- **worker:** 97.5% CPU (loop 94%).
- **alert pass:** 595–1,921 s.
- **WLC poll:** avg 372 s, max 899 s.
- **switches:** ≈ 66 s average.
- **syslog:** 2.91 / 3 GiB.
- **ClickHouse:** 169–301% CPU, 3 memory errors / 24 h.

**Lab, mechanism of RC-1** (`isolation_bench`, real SNMPv3 agent, 2,000-await alert-pass stand-in):

| | Alert pass | Await delay p50 / p99 |
|---|---|---|
| idle loop (reference) | 2.46 s | 0.19 / 1.21 ms |
| SNMP on the same loop (before) | **17.21 s** | 7.63 / 16.15 ms |
| SNMP in its own process (after) | **2.31 s** | 0.15 / 0.26 ms |

**Syslog per parser, from the measured components:**
- **steady state:** ≈ 273 → ≈ 230 MiB (smaller caches);
- **worst case:** ≈ 503 → ≈ 300 MiB (3-batch buffer);
- **whole container worst case:** ≈ 3.2 → ≈ 2.0 GiB.

This is an estimate from measured parts; confirm with `docker stats` after deploy.

**Rules, expected:** `new_country` + `new_port` from ≈ 62 s and 1.86 billion rows per pass to rollup lookups plus at
most 3 raw hours each.

**Production, after** (measured 2026-11-12 07:12 UTC, one hour window, 3 pollers):

| | Before | After |
|---|---|---|
| worker CPU / loop lag p95 | 97.5% / seconds | 68% / 0.006 s |
| alert pass | 595–1,921 s | 25–39 s |
| WLC quick metrics age (after RC-13) | 10–15 min | 45–65 s |
| switch polls (676 in 1 h) | ≈ 66 s average | 9.4 s average, 27.6 s max, 0 failed |
| WLC polls (32 in 1 h) | avg 372 s, max 899 s | avg 94 s, max 254 s, 0 failed |
| WLC full poll (all wireless tables) | 550–900 s | 235–249 s, every ≈ 5 min |
| `switch_stale_metrics` alerts | firing | 0 in the last hour |
| syslog memory | 2.91 / 3 GiB | 2.0 / 3 GiB |
| ClickHouse | 169–301% CPU, 6.2 GiB, code 241 errors | 110% CPU, 4.7 GiB |

**WLC, not yet at its 30-s target.** Walking the wireless tables concurrently (RC-11) did not shorten the full poll
much: the walks share one poller core, and pyasn1 decoding is CPU-bound, so each walk took longer when they overlapped
(wireless_client 96 → 196–216 s, wireless_radio_rf 26 → 165–189 s). The quick controller metrics (system, CPU,
interfaces, AP list) are collected only between the heavy polls, so they refresh about every 4–6 minutes, down from
10–15.

**WLC after the split (RC-13), measured 2026-11-13 16:58 UTC, 10 minutes after deploy:**
- **quick poll:** every ≈ 30 s (average gap 37 s; the one 193-s gap spans the deploy restart), each taking 1–26 s;
- **wireless job:** 48–56 s instead of 235–249 s, because it now runs on another poller core instead of competing
  with the quick poll;
- **data age:** APs and radios 45 s, clients and radio RF 65 s, RF neighbours and radio metadata within their 900-s
  interval;
- **failures:** 0 failed runs, no `switch_stale_metrics` alerts, no tracebacks;
- **rest of the fleet:** 132 polls in 15 minutes, 14.3 s average, 0 failed.

## Tests

- **New:** `tests/test_performance.py`, 12 tests, all pass.

  | Test | Covers |
  |---|---|
  | worker roles / `loop_plan` | the poller and core processes run the right loops |
  | loop monitor | detects a blocked loop |
  | scheduler at **100, 500 and 1,000 devices**, one unreachable and one never-answering device among them | concurrency ≤ 16, every healthy device polled before the slow one's budget expires, the slow one cut off and recorded as a timeout, no lease left behind |
  | `new_country` / `new_port`, rollup vs raw | identical detections |
  | `_learning_ok` | reads the minute rollup |
  | identity per-day baseline | equals the full baseline; days cached, only edges re-queried |
  | syslog buffer cap, backpressure, memory release | bounded |
  | syslog burst: 60,000 lines, a third malformed | buffer never above its cap, every line accounted for (inserted / duplicate / parse error), none dropped |
  | ClickHouse limits | present and configurable |
  | staleness interval and threshold | uses the configured interval and the poll budget |
- **Updated:** migration list (17) in `test_storage_analytics`; `test_secret_files` service map (`poller`). Fixed a
  date-dependent RF heatmap test (its 7-day window from today no longer held the fixture's fixed date).
- **Full backend suite:** **521 passed, 1 skipped**.
- **Lint:** clean on every changed file.

## Remaining risks and follow-ups

1. **SNMP CPU still grows with the fleet.** RC-1's fix isolates and scales it horizontally (`--scale poller=N`), but
   pyasn1 stays CPU-heavy. For thousands of devices, evaluate a C-backed SNMP library (net-snmp bindings) or a compiled
   decoder. That is a larger change, not made here.
2. **Metrics are in logs, not a metrics endpoint.**
   - **Already covered:** per-rule timings, loop lag, parser RSS and syslog counters are logged, and poll durations
     are in `switch_poll_runs`.
   - **Not done:** a Prometheus-style endpoint with the requested metric names. That is the next observability step;
     it was left out to avoid adding a dependency without agreement.
3. **Not yet optimised:**
   - `new_domain` (4.8 s, 64 million rows);
   - the SD-WAN health queries that regex-extract from `raw` (≈ 380 runs a day each, ≤ 2.5 s);
   - the port-scan rule's 30-day query noted in the policy-usage work.
4. **H-1 (JSON decoding in one profile sample)** is unconfirmed; the new per-rule and loop-lag logging will show it if
   it recurs.
5. **Memory limits (RC-8) are not changed yet.** Re-measure for 24 h, then apply the plan's limits.
6. **ClickHouse 24.8 is past end of support** (security pass): upgrade to 25.8 LTS separately, tested on a copy of the
   data.
7. **Graceful shutdown:** the syslog parsers already drain and flush on stop. A worker stop cancels in-flight polls;
   their leases expire and the devices are polled again on the next pass.

## Production recommendation

Deploy as one change; migration 17's backfill adds 1–2 minutes to `migrate`. Then run the DEPLOYMENT_GUIDE.md
checks after 15 minutes and again after 24 hours. Expected, if the root causes are right:
- **worker CPU:** well below one core;
- **alert passes:** ≈ 1–2 minutes;
- **WLC polls:** well inside the 900-s budget, with no staleness alerts;
- **memory errors:** no further ClickHouse code 241;
- **syslog:** below ≈ 2.2 GiB after backlogs.

If any of these is not met, the per-rule timings and loop-lag lines identify the next cause.
