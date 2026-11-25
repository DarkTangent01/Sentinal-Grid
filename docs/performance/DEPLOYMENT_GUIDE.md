# Deploying the performance remediation

What changes: [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md). Why: [INITIAL_AUDIT.md](INITIAL_AUDIT.md).

## Summary of operational changes

| Change | Effect on the running system |
|---|---|
| New service `poller` (same backend image, `WORKER_ROLES=snmp`) | SNMP switch / WLC polling moves out of `worker`. One more container. |
| `worker` gets `WORKER_ROLES=core` | It no longer polls switches. |
| ClickHouse migration 17 (`migrate`) | Two small additive tables + views (`traffic_country_hourly`, `traffic_port_hourly`) and a one-time backfill, one day per statement. No change to `events`. |
| Per-query ClickHouse limits | 2 GiB memory per query (larger aggregations spill to disk), 60 s. |
| Syslog | Buffer cap 3 × batch (was 10 ×), dedupe window and GeoIP cache 50k (were 200k), memory handed back after a backlog. |
| `switch_stale_metrics` | Uses the device's configured interval and its poll budget. |
| Wireless controllers | Two jobs per Cisco controller: the quick poll (system, CPU, interfaces, APs, radios, WLANs) and a separate wireless job for the client / RF tables, each with its own lease (`switches.wireless_lease_until`, PostgreSQL migration 0028, one nullable column). Poll runs of the second job have `kind = 'wireless'`. |
| Poller shutdown | A stopping poller releases the leases of its in-flight polls, so a restart no longer leaves a device unpolled for its whole budget. |

## Environment variables (all optional; defaults shown)

| Variable | Default | Purpose |
|---|---|---|
| `POLLER_REPLICAS` | `1` | Poller processes. Production: `3` (SNMP decoding saturates one core with ~13 devices). |
| `SWITCH_MAX_CONCURRENT_POLLS` | `16` | Poll slots per poller process; a replica leases at most this many devices at a time. Production: `5`, so the fleet spreads across replicas. |
| `WORKER_ROLES` | `all` | `core`, `snmp` or `all`. Compose sets `core` on `worker` and `snmp` on `poller`. A single-container install keeps `all`. |
| `SWITCH_WLC_SPLIT_WIRELESS` | `true` | `false` polls a controller's client / RF tables inside its quick poll again (the previous behaviour). |
| `ALERT_BASELINE_FROM_ROLLUP` | `true` | `false` restores the raw-event baselines for `new_country` / `new_port`. |
| `CLICKHOUSE_QUERY_MAX_MEMORY` | `2147483648` | Bytes per query; `0` = unlimited (the previous behaviour). |
| `CLICKHOUSE_QUERY_TIMEOUT_SECONDS` | `60` | Unchanged value, now configurable. |
| `SYSLOG_BUFFER_MAX_EVENTS` | `0` (= 3 × `SYSLOG_BATCH_SIZE`) | `100000` restores the previous cap. |
| `SYSLOG_DEDUPE_WINDOW` | `50000` | Per parser process. |
| `GEOIP_CACHE_SIZE` | `50000` | Per parser process. |

## Deployment order

1. **Backup** (the deploy script does it unless `SKIP_BACKUP=1`).
2. **Deploy:**
   ```bash
   ./scripts/deploy.sh --apply
   ```
   `migrate` runs ClickHouse migration 17 first. Its backfill is roughly 1–3 s per day of traffic, so expect up to
   1–2 minutes for 13 days. The running `api` / `worker` keep serving until `migrate` completes. Compose then creates
   `poller` and recreates `worker` with `WORKER_ROLES=core`.
3. **Nothing else is required.** Devices, rules and data are unchanged.

## Health verification (on the server)

Services: `poller` must be healthy, and `worker` and `syslog` healthy as before.

```bash
docker compose ps
```

The split happened:

```bash
docker compose logs --since 5m worker poller | grep "worker started"
```

Expect `roles core` and `roles snmp`.

Migration 17 applied and backfilled:

```bash
docker compose logs migrate | grep -E "migration 17|backfilled"
```

Event-loop lag, worker and poller. Expect `p95 <0.05s` on `worker`; the old process would have shown seconds.

```bash
docker compose logs --since 10m worker poller | grep "event loop lag"
```

Alert passes and their slowest rules. Expect a pass of about 1–2 minutes instead of 10–30, and `new_country` /
`new_port` no longer at the top.

```bash
docker compose logs --since 30m worker | grep "alert evaluation finished" | grep -o "finished in [0-9.]*s\|_slowest.*"
```

Poll durations. Expect the WLC well under its 900-s budget and access switches near their real collection time:

```bash
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT s.name, count(*), round(avg(r.duration_ms)) avg_ms, max(r.duration_ms) max_ms, sum(CASE WHEN r.ok THEN 0 ELSE 1 END) failed FROM switch_poll_runs r JOIN switches s ON s.id=r.switch_id WHERE r.started_at > now()-interval '"'1 hour'"' GROUP BY s.name ORDER BY max_ms DESC"'
```

CPU and memory. Expect `worker` well below 100%, `poller` at roughly ≤ 1 core, and `syslog` well under its limit
after backlogs:

```bash
docker stats --no-stream
```

ClickHouse query costs. Expect the 1.28-billion and 579-million-row shapes to be gone. The full query is in
INITIAL_AUDIT.md's measurements; the short form:

```bash
. scripts/lib-env.sh && chq "SELECT left(query,80), count(), round(avg(query_duration_ms)) avg_ms, formatReadableQuantity(max(read_rows)) FROM system.query_log WHERE event_time > now()-INTERVAL 1 HOUR AND type='QueryFinish' GROUP BY 1 ORDER BY sum(query_duration_ms) DESC LIMIT 10 FORMAT PrettyCompact"
```

## Measure, then size (Phase 7)

After 24 h, re-measure `docker stats` and decide the memory limits. The proposal in REMEDIATION_PLAN.md keeps the
total under the host's 15 GiB. Today the limits add up to 17.25 GiB, so the host is oversubscribed. Change one service
at a time:

```bash
docker compose up -d <service>
```

## Rollback

| To undo | Do |
|---|---|
| the process split | Set `WORKER_ROLES: all` on `worker` (or remove the line), remove the `poller` service, `docker compose up -d worker` and `docker compose rm -sf poller`. |
| the controller split | `SWITCH_WLC_SPLIT_WIRELESS=false`, then `docker compose up -d poller`. Migration 0028's column can stay. |
| rollup baselines | `ALERT_BASELINE_FROM_ROLLUP=false` in `.env`, then `docker compose up -d worker`. Migration 17's tables can stay; nothing else uses them. |
| query limits | `CLICKHOUSE_QUERY_MAX_MEMORY=0`. |
| syslog sizes | `SYSLOG_BUFFER_MAX_EVENTS=100000`, `SYSLOG_DEDUPE_WINDOW=200000`, `GEOIP_CACHE_SIZE=200000`. |
| everything | Redeploy the previous commit. Migration 17 is additive; its tables do not affect the previous code. |

No data is deleted by the change or by its rollback.

## Scaling notes

- **More devices:** raise `POLLER_REPLICAS` (and keep `SWITCH_MAX_CONCURRENT_POLLS` × replicas ≥ the devices you want polled at once). Each switch is claimed with a database lease
  (`switches.lease_until`), so replicas never poll the same device. One poller handled 13 devices at about 75% of a
  core before the split. That figure included the starvation overhead, so it is an upper bound; plan about one poller
  per 100 devices of this size and verify with `docker stats`.
- **Inside a poller,** concurrency is bounded by `SWITCH_MAX_CONCURRENT_POLLS` (default 16). A slow or unreachable
  device is cut off at its budget (`SWITCH_POLL_TIMEOUT_SECONDS` / `SWITCH_WLC_POLL_TIMEOUT_SECONDS`) and backs off,
  without holding up the others (tested with 100 / 500 / 1,000 devices).
