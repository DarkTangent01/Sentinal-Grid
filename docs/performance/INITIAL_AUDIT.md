# Performance audit: root-cause analysis (2026-11-10)

Scope: the production symptoms reported for the worker (100% CPU, 7–30 min alert passes), syslog (≈3 GiB of a 3 GiB
limit), ClickHouse (≈3 cores, `MEMORY_LIMIT_EXCEEDED`) and SNMP polling (WLC-ZOMATO-1 polls of 12–15 min, stale data).

Every finding below is labelled **Confirmed** (measured on production or reproduced) or **Hypothesis** (inferred,
not yet measured). All production measurements were read-only:
- `docker stats`, container logs, `/proc`;
- ClickHouse `system.query_log`;
- PostgreSQL `switch_poll_runs`;
- one-off containers running read-only measurement scripts;
- a 2 × 60 s py-spy sample of the worker. This was approved: a non-blocking sidecar, removed afterwards.

## Architecture as deployed

| Process | What it runs | Concurrency model |
|---|---|---|
| `worker` | **every** background loop in one process: FortiGate API polling, policy sync, alert evaluation (127 rules), retention, NGEN jobs (notifications, TI feeds, assets, reports…), ICMP, **SNMP switch / WLC polling**, NMS service checks, TACACS+, IaC | one asyncio event loop, one core (GIL) |
| `syslog` | receiver + `SYSLOG_WORKERS=6` parser processes (normalise, enrich, insert) | multiprocessing, chunks via queues |
| `clickhouse` | storage, alert queries, dashboards | 8 CPU / 8 GiB container, server cap 6.4 GiB |
| `api`, `traps`, `ingress`, `web`, `postgres`, `tacacs` | not implicated by the measurements | |

The host has **24 vCPU and 15 GiB RAM**. The container memory limits add up to **17.25 GiB**, which oversubscribes RAM.

## Measured baseline (production, 2026-11-10)

| Metric | Value |
|---|---|
| worker CPU | 97.5% (the event-loop thread alone 94.1%; other 32 threads ≈ 0) |
| alert evaluation pass (interval 60 s) | 595–1,921 s (last 3 h) |
| all 127 rules' detection functions, run alone in a separate process | **95.8 s wall, 12.7 s CPU** |
| syslog memory | 2.914 GiB / 3 GiB: 6 parsers × 458–487 MiB + receiver 182 MiB |
| ClickHouse | 169–301% CPU, 6.19 GiB / 8 GiB, server cap 6.40 GiB, 3 × code 241 (memory) in 24 h |
| SNMP | 12.0 requests/s, 399 polls/h, 108 requests/poll on average |
| WLC-ZOMATO-1 | 190 polls / 24 h, avg 372 s, max 899 s (`poll exceeded 900s`), ≈2,500 requests per full poll |
| access switches | avg ≈ 66 s per poll (interval 60 s), max 146–191 s, ≈ 65 failed polls / 24 h each |

## Root causes

### RC-1: SNMP decoding saturates the worker's only event loop, and starves everything else. **Confirmed, Critical**

**Evidence:**
- **py-spy, 1,753 samples:**
  - 62.7% `pyasn1` + 12.6% `pysnmp`, i.e. 75% of the worker's CPU is BER encode / decode of SNMP packets in pure Python;
  - app code 11.0%, database drivers ≈ 5%, alert engine < 1%;
  - 0% of samples idle in `select`: the loop never waits.
- **Effect on the alert pass:** its own cost is 96 s (12.7 s CPU), but it takes 600–1,900 s in the worker. Each `await`
  waits behind SNMP decoding.
- **Effect on the WLC:**
  - **per request:** 771 s ÷ 2,591 requests ≈ 0.3 s per request to a LAN device, against 2–6 ms in an uncontended
    process (lab benchmark);
  - **trivial groups:** a one-GET `system` group took 227–824 ms;
  - **every switch:** all of them average ≈ 66 s per poll regardless of size, a shared-resource symptom rather than a
    device symptom.

**Why it scales badly:** SNMP CPU grows linearly with devices and table sizes, and it shares one core with alerting,
notifications and every other loop. The number of devices at which everything degrades is about where production
already is (13 devices).

### RC-2: Two alert rules rescan 30 days of raw traffic every pass. **Confirmed, High**

| Rule | Query cost per run | Cause |
|---|---|---|
| `new_country` | 32.5 s, reads **1.28 billion rows** (p50 36.8 s, max 44.5 s) | `NOT IN (SELECT DISTINCT dst_country FROM events … 30 days)` |
| `new_port` | 29.2 s, 579 million rows | `base AS (SELECT DISTINCT src_ip, dst_port FROM events … 30 days)` |
| `_learning_ok` (both) | full scan of `min(event_time)` over every traffic row | no rollup used |
| `new_domain` | 4.8 s, 64 million rows | 7-day DNS baseline |

Together that is ≈ 65 s of the 96-s pass, at 8 ClickHouse cores, every pass. It is the largest analytical CPU load.

### RC-3: `identity_unusual_login` loads its whole baseline into Python every pass. **Confirmed, High**

- **What it does:** `auth_events(t0 − 30 days, t0)` returns every authentication event of 30 days with about 20
  `extract(raw, …)` regexes per row and `ORDER BY event_time`. Python then rebuilds the per-user baseline from it.
- **Memory:** the sort over 30 days of system events is what hit `MEMORY_LIMIT_EXCEEDED (6.41 GiB / 6.40 GiB)` when it
  coincided with other heavy queries.
- **Accuracy bug:** the query ends with `LIMIT 200000` on an ascending sort, so once a month holds more than 200k
  authentication events, the **newest** part of the baseline is silently dropped.

### RC-4: Syslog memory sits at the limit by configuration, not by leak. **Confirmed, High**

Measured per parser process, with production data (GeoIP databases, 126k threat-intel indicators):

| Component | MiB |
|---|---|
| Python + app imports | 72 |
| Enricher + threat intel | 87 |
| GeoIP LRU cache (200k entries) | 57 |
| dedupe set (200k event ids) | 34 |
| one 10k-event batch | 23 |
| **steady state** | **≈ 273** |
| insert buffer cap: `10 × batch` = 100k events if ClickHouse stalls | **+ ≈ 230** |

The arithmetic, 6 × (273 + 230) + 182 ≈ 3.2 GiB, matches the observed 2.91 GiB against the 3 GiB limit. Python does not
return freed memory to the OS after a buffer peak, so the RSS stays at the peak.

**Secondary issue:** the dedupe set is per process, and chunks are distributed round-robin, so a duplicate usually lands
in a different process anyway. ReplacingMergeTree deduplicates on merge. The 200k-entry sets cost 200 MiB for little
benefit.

### RC-5: ClickHouse has no per-query limits. **Confirmed, High**

- **Settings:** `max_memory_usage = 0` (per query) and server-wide `max_execution_time = 0`. The client sets 60 s;
  nothing sets memory.
- **Effect:** one heavy query (RC-2, RC-3) can take most of the 6.4 GiB server budget. The other concurrent queries then
  fail with code 241, including syslog inserts (one `clickhouse insert … failed … Memory` in the last hour).
- **No spill to disk:** neither `max_bytes_before_external_group_by` nor `max_bytes_before_external_sort` is set, so
  large aggregations cannot spill.

### RC-6: The WLC's wireless groups are the WLC's own cost, multiplied by RC-1. **Confirmed, Medium**

- **Per-group times:** RF neighbours 146–245 s, clients 176–206 s, radio RF 83–187 s, APs 25–47 s.
- **Sequential:** the groups run one after another; the total ≈ the sum.
- **Why so many requests:** the multi-column table walks fit 60 varbinds per response (the device's default 1,500-byte
  SNMP packet), so the WLC needs ≈ 2,500 requests.
- **Measure, then decide:** once RC-1 is removed (≈ 5 ms per request), the same walk is ≈ 15–30 s. Measure after RC-1
  before considering anything device-side.

### RC-7: The staleness alert uses the wrong interval and a threshold blind to poll duration. **Confirmed, Medium**

- **Wrong interval:** `switches/alerts.py` uses `max(60, poll_interval_seconds)`. A device configured for 30 s is
  reported as "interval 60s", while the poller uses `max(30, …)`. This is the reported inconsistency.
- **Threshold blind to poll duration:** the threshold (`3 × interval + 60 s`) ignores how long a poll may legitimately
  run. A WLC with a 900-s poll budget is flagged stale during a single healthy poll.

### RC-8: The memory limits exceed host RAM. **Confirmed, Medium**

The container limits total 17.25 GiB on a 15 GiB host. Under pressure the kernel, not Docker, picks what to kill.

## Hypotheses (not confirmed; to measure after the fixes)

- **H-1:** the 15% JSON decoding and 9% PostgreSQL row fetching in the *first* py-spy sample come from a periodic job
  (notifications outbox every 15 s, or switch `health` / `group_state` JSON columns). They did not reproduce in the
  second sample. Measure with the per-job timing added in this change.
- **H-2:** with RC-1 fixed, one SNMP process can handle about 100–150 devices of this size before its own core
  saturates (12 req/s ≈ 75% of a core today). Thousands of devices need several poller processes. The existing
  database lease (`switches.lease_until`) already allows replicas.

## Not a cause (checked)

- **FortiGate API log pulls:** disabled on all three firewalls (`api_log_pull = false`).
- **Alert rules' own queries,** apart from RC-2 and RC-3: under 3 s each in isolation.
- **PostgreSQL:** 1–2% CPU, 264 MiB.
- **Leaks:** syslog, worker and ClickHouse show `OOMKilled=false` and 0 restarts. The memory is configured, not leaked.

## Affected files

| Area | Files |
|---|---|
| RC-1 | `app/worker.py`, `app/switches/poller.py`, `docker-compose.yml` |
| RC-2 | `app/alerts/engine.py`, `app/db/ch_schema.py` |
| RC-3 | `app/identity.py`, `app/alerts/engine.py` |
| RC-4 | `app/ingest/pipeline.py`, `app/enrich/geo.py`, `app/syslog_server.py`, `app/config.py` |
| RC-5 | `app/db/ch.py`, `app/config.py` |
| RC-7 | `app/switches/alerts.py` |
| RC-8 | `docker-compose.yml` |
