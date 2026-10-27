# Architecture and implementation plan

## 1. Components

```
 FortiGate(s) ──syslog UDP/TCP 514──► ingress (rsyslog) ──relay TCP 5515──► syslog service ──┐
      ▲                       (queue, spills to disk)          (parse → normalize → dedupe → batch)
      │ HTTPS REST (GET only, Bearer token)             ▼
      └──────────── worker ───────────────────────►  ClickHouse  (events, events_minute, device_metrics)
                    │  health polling, optional               ▲
                    │  API log pull, alert engine,            │ parameterized aggregations
                    │  retention                              │
                    ▼                                         │
                PostgreSQL ◄──────────── api (FastAPI) ───────┘
   (users, firewalls, encrypted tokens,      ▲
    rules, alerts, audit, retention)          │ /api (cookie session + CSRF)
                                         nginx (TLS, static React UI, rate limits)
```

| Service | Process | Responsibility |
|---|---|---|
| `ingress` | `rsyslogd` (deploy/ingress) | Owns the published syslog port (UDP + TCP 514). Forwards every line unchanged, prefixed with the sender's IP, to the syslog service over TCP, queueing in memory and on disk while that service is unavailable. Its image never changes with code deploys, so it is not restarted: deploys lose no logs, and UDP senders' connection-tracking entries stay valid (recreating the container that owns a published UDP port black-holes long-lived UDP flows until the kernel entry expires — about 10 minutes for a busy firewall). |
| `syslog` | `python -m app.syslog_server` | UDP + TCP (newline or RFC 6587 octet-counted) receiver (relay port 5515 accepts frames only from the ingress container, whose frames name the original sender); maps each log to a registered firewall by `devid` (serial) → `devname` → sender IP; drops unknown devices unless `SYSLOG_ALLOW_UNKNOWN_DEVICES=true`; batches inserts; records per-firewall ingestion health. |
| `worker` | `python -m app.worker` | Polls FortiGate REST monitor endpoints on each device's interval (bounded concurrency, shardable with `WORKER_SHARD/WORKER_SHARDS`); optional best-effort log API pulls; alert evaluation every `ALERT_INTERVAL_SECONDS`; retention every `RETENTION_INTERVAL_SECONDS`; demo feed when `DEMO_MODE=true`. |
| `api` | `uvicorn app.main:create_app --factory` | Auth, RBAC, firewall registry, Test Connection, analytics, explorer, investigations, alerts, admin. |
| `migrate` | `python -m app.migrate` | Alembic (PostgreSQL) + versioned ClickHouse migrations + seed (default rules, retention, bootstrap admin). |
| `web` | nginx | TLS termination, security headers, login/API rate limits, SPA. |

Redis is **not** used: the worker coordinates through PostgreSQL and static sharding, and the ingress queue absorbs syslog-service restarts. A message queue (Kafka or Redis Streams) between syslog receivers and ClickHouse is the recommended addition beyond roughly 50k events/s or when running several receivers behind a load balancer.

## 2. FortiOS capabilities that shaped the design

* **The REST API is not a log stream.** `/api/v2/log/{device}/{type}[/{subtype}]` returns pages of *stored* logs (memory, disk or FortiAnalyzer) newest-first, using `start`/`rows`. Large searches run as background sessions (`session_id`, `ready`, `completed`). Logs can roll over between polls, and memory logging holds very little. For that reason **syslog is the primary source** for traffic, DNS, web and UTM logs, and API log pulls are an optional, best-effort supplement (per device, off by default).
* **Current sessions ≠ traffic history.** `/api/v2/monitor/firewall/session` is a point-in-time snapshot. It is probed during Test Connection but is never written as historical traffic.
* **DNS queries are not in traffic logs.** Individual queries appear only in DNS-filter logs (`type=utm subtype=dns`), which requires a DNS-filter profile on the policy with `log-all-domain enable`. DNS-database config (`cmdb/system/dns-database`) and DNS proxy settings are configuration, not telemetry, and are not used as query data.
* **URLs.** Web-filter logs carry `hostname` and `url`. In FortiOS `url` is usually the **path** only; the full URL is present only for some inspection modes and logging settings. The SIEM stores both fields as logged, sets `url_is_full=1` only when the logged value has a scheme, and never builds a URL from a domain.
* **Interim traffic logs** carry cumulative `sentbyte`/`rcvdbyte` plus `sentdelta`/`rcvddelta`. The normalizer stores the deltas when present so that summing records never double-counts long sessions.
* Monitor endpoints used: `monitor/system/status` (identity, version, serial), `monitor/system/resource/usage` (CPU, memory, sessions), `monitor/system/interface` (link state and counters), `cmdb/firewall/policy` (policy names, read-only). Availability is probed per device and stored as `supported | forbidden | not_found`.

Endpoint paths follow the FortiOS 7.x REST API reference (Fortinet Developer Network). FNDN requires a login, so the exact response schema of every version could not be re-verified while building this. The client therefore parses defensively and records unsupported endpoints instead of guessing. Run **Test Connection** against each device type you deploy.

## 3. Data flow and idempotency

1. Parse (`app/ingest/parser.py`): strips the RFC 3164/5424 envelope and parses `key=value` with quoted values.
2. Normalize (`app/ingest/normalize.py`): maps to the common schema, converts timestamps to UTC (`eventtime` in s/ms/µs/ns, or `date`+`time`+`tz`), and normalizes action and severity while keeping `orig_action` and `orig_severity`. Missing values are left empty or NULL. If no timestamp exists, ingest time is used and `parser_version` is suffixed `+ingest-ts`.
3. Fingerprint: SHA-256 over identity fields (`devid`, `eventtime`, `logid`, `sessionid`, the 5-tuple, bytes, `qname`, `url`, …) stringified, so syslog and API copies of the same log hash identically and distinct sessions never collide.
4. Dedupe: in-memory LRU (200k IDs) per receiver, plus ClickHouse `ReplacingMergeTree(ingest_time)` keyed by `(category, firewall_id, event_time, event_id)`. `FINAL` is off by default (`CLICKHOUSE_QUERY_FINAL=false`) because it is very expensive at tens of millions of rows per day. Duplicates are already suppressed at ingest and collapsed by background merges. Enable it only for small deployments that need guaranteed exact counts during a re-ingest.
5. Insert batches (`SYSLOG_BATCH_SIZE`, `SYSLOG_FLUSH_SECONDS`). A failed insert re-queues the batch.

## 4. Normalized schema (ClickHouse `events`)

| Group | Columns |
|---|---|
| Identity | `event_id`, `event_time` (UTC, ms), `ingest_time`, `category` (traffic, dns, web, security, system), `event_type`, `event_subtype`, `log_id`, `source` (syslog, api_log, demo), `parser_version` |
| Device | `firewall_id`, `firewall_name`, `site`, `devid`, `vdom` |
| Network | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `proto_name`, `src_intf`, `dst_intf`, `nat_src_ip/port`, `nat_dst_ip/port` |
| Policy / verdict | `policy_id`, `policy_name`, `action` (accept, close, timeout, reset, deny, block, allow, monitor, other), `orig_action`, `severity` (critical … informational), `orig_severity` |
| Session | `session_id`, `sent_bytes`, `rcvd_bytes`, `sent_pkts`, `rcvd_pkts`, `duration` |
| App | `app`, `app_id`, `app_cat`, `service` (as logged) |
| Web | `hostname`, `url` (as logged), `url_is_full`, `http_method`, `url_category` |
| DNS | `dns_qname`, `dns_qtype`, `dns_rcode`, `dns_resolved[]`, `dns_latency_ms`, `dns_qname_len`, `dns_entropy` (Shannon entropy of the subdomain part) |
| Security | `threat` (attack, virus, app or category), `user`, `msg` |
| Raw | `raw` (original line, ZSTD-compressed) |

`PARTITION BY (category, toYYYYMMDD(event_time))` gives independent per-category retention by dropping whole partitions. Bloom-filter skip indexes cover `src_ip`, `dst_ip`, `hostname` and `dns_qname`. The `events_minute` materialized view keeps a per-minute ingest rollup (storage and ingest-rate page). The
`events_1m` rollup (SummingMergeTree, per minute × category × firewall × site × action × source) serves dashboard KPIs
and time charts. Whole minutes come from the rollup and the partial minutes at both window edges from raw events,
so the results are exact. Queries that filter on other fields (IP, port, domain, …) read raw events. Distinct
session and domain counts use `uniqCombined64` (≈1 % error, shown as "≈" in the UI); distinct IP counts are exact. `device_metrics` holds CPU, memory and session history from the REST API (90-day TTL).

## 5. Retention model

| Category | Default | Source |
|---|---|---|
| traffic | 30 days | `retention_policies` (PostgreSQL), editable in Settings → Retention |
| dns | 30 days | |
| web | 90 days | |
| security | 365 days | |
| system | 365 days | |

The worker drops only partitions whose whole day is older than the cutoff, and writes a `retention_runs` row (partitions, row count, status) for every run that removed data or failed. Nothing is deleted silently. Policy changes are audited.

## 6. Phased plan (as implemented)

| Phase | Scope | Status |
|---|---|---|
| 1 | FastAPI app, PostgreSQL models plus Alembic, auth (argon2, JWT cookie, CSRF, lockout), RBAC, firewall registration with Fernet-encrypted tokens | Done |
| 2 | FortiGate client (pooling, TLS verification, token bucket, retries with backoff), Test Connection, health polling, capability probing | Done (verified with mocks; **not** against hardware) |
| 3 | Syslog receiver, parser, normalizer, dedupe, ClickHouse storage | Done (verified end to end locally over UDP) |
| 4 | DNS, web and security normalization; best-effort API log pull | Done |
| 5 | Dashboard, top-N pages, web/DNS/security pages, explorer, IP investigation | Done |
| 6 | Alert engine (11 rules), grouping, suppression, triage workflow, CSV export | Done |
| 7 | Docker Compose, nginx TLS, backups, docs, tests | Done (compose not executed here: no Docker on the build machine) |
