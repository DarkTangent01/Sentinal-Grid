# Operations: troubleshooting, backup and known limitations

## Troubleshooting

| Symptom | Checks |
|---|---|
| Firewall API status `auth_error` | Token revoked or expired; API user's trusted hosts exclude the SIEM IP; wrong VDOM. Regenerate with `execute api-user generate-key <user>`. |
| `unreachable` + "TLS certificate verification failed" | FortiGate uses its factory self-signed certificate. Install a certificate from your CA on the FortiGate (`config system global` → `admin-server-cert`) or mount the issuing CA at `deploy/certs/fortigate-ca/` and set the device's CA bundle path (for example `/certs/ca.pem`). |
| Endpoint shows `forbidden` | Access profile lacks read permission for that group (sysgrp, netgrp, fwgrp, loggrp). |
| API OK but "no logs received" | Expected until syslog is configured. Check `config log syslogd setting`; check that UDP/TCP 514 reaches the host (`tcpdump -ni any port 514`); check `docker compose logs syslog` counters. `unknown_device` rising means the sending IP or serial is not registered: run Test Connection (records the serial) or add the IP under *Syslog source IPs*. |
| DNS page empty | No DNS-filter logs: apply a DNS-filter profile with `log-all-domain enable` to the relevant policies. |
| Only hostnames on the Web page | Normal for many FortiOS configurations; enable `log-all-url` and, where appropriate, deep inspection plus extended logging. |
| `parse_errors` rising | Syslog format is not `default` (CSV or CEF are not supported): `set format default`. |
| Ingestion lag growing | ClickHouse under-resourced or receiver CPU-bound: check `docker stats`; raise `SYSLOG_BATCH_SIZE`; add receivers behind a UDP load balancer. |
| Dashboard slow or stuck on "Loading…" | Check running queries: `SELECT elapsed, query FROM system.processes`. KPIs and time charts use the `events_1m` rollup, so they should take well under 1 s; top-N tables scan raw events. Keep `CLICKHOUSE_QUERY_FINAL=false` at high volume, give ClickHouse more CPU/RAM, or narrow the range or firewall filter. |

Useful commands:
```bash
docker compose ps
docker compose logs -f syslog worker api
docker compose exec clickhouse clickhouse-client -u siem --password "$CLICKHOUSE_PASSWORD" -q "SELECT category, source, count() FROM siem.events GROUP BY ALL"
```

## Upgrading

```bash
# on your workstation: sync code (keeps .env, certs, backups on the server)
rsync -av --exclude '.venv' --exclude 'node_modules' --exclude 'frontend/dist' --exclude '.env' --exclude '__pycache__' \
  --exclude '.pytest_cache' --exclude '.claude' --exclude '.dev' --exclude 'backups' --exclude 'deploy/certs' ./ <user>@<server>:~/fortisiem/
# on the server
cd ~/fortisiem
docker compose stop syslog worker        # pause ingestion so ClickHouse migrations/backfills are exact
docker compose build
docker compose run --rm migrate          # applies pending migrations (watch the log)
docker compose up -d
```
Releases that add ClickHouse migrations with a backfill (for example v4, the `events_1m` rollup) can take several
minutes on large tables, because the backfill reads every stored event once. FortiGate syslog in `reliable` mode
reconnects automatically. Logs sent while the receiver is stopped may be lost, so keep the window short.

## Backup and restore
- `scripts/backup.sh` → `backups/<UTC timestamp>/postgres.dump` (pg_dump custom format) plus `backups/clickhouse/<timestamp>.zip` (ClickHouse native `BACKUP DATABASE`).
- `scripts/restore.sh <timestamp>` stops the ingest and API services, restores both databases, and restarts them.
- Back up `TOKEN_ENCRYPTION_KEY` and `.env` separately. Without the key, encrypted tokens cannot be decrypted, and each FortiGate must be given a new token.
- Docker volumes `fortisiem_pgdata` and `fortisiem_chdata` hold live data; snapshotting them while services are stopped is an alternative.

## Storage monitoring
Settings → Storage shows rows, disk usage, partitions and date range per category, plus ClickHouse table sizes. Retention runs are listed under Settings → Retention.

## Scaling notes
- Worker: run several replicas with `WORKER_SHARDS=N` and a distinct `WORKER_SHARD` each (firewall id modulo N). Only shard 0 runs alerts and retention.
- Syslog: stateless apart from the dedupe cache. Run several behind a UDP/TCP load balancer; ReplacingMergeTree collapses cross-receiver duplicates.
- ClickHouse: one node handles hundreds of firewalls at typical rates. For thousands, use a ClickHouse cluster (ReplicatedReplacingMergeTree plus a Distributed table) and put Kafka in front of the inserts.

## Known limitations
1. **Not tested against real FortiGate hardware.** API behaviour is verified with mocks built from FortiOS 7.x documentation and community references. The live test (`pytest -m live`) is skipped unless credentials are supplied.
2. **The Docker Compose stack was not started in the build environment** (Docker was unavailable). The application was verified as a single process with embedded ClickHouse (chdb) and SQLite. Image tags are pinned; confirm they pull in your registry.
3. API log pulling is best effort: newest-first paging with an `eventtime` high-water mark can miss logs that roll over between polls. Use syslog for completeness.
4. Only the FortiGate `default` syslog format is parsed (no CEF or CSV) and there is no native TLS syslog listener.
5. No native FortiAnalyzer JSON-RPC connector; forward from FortiAnalyzer via syslog instead.
6. One VDOM per registration (register each VDOM as its own entry with the same host).
7. Alert `event_count` is the peak count in a detection window, not a lifetime total; use *View related events* for exact totals.
8. Session counts rely on FortiGate `sessionid`, unique per firewall within the time window. IDs can repeat after reboots over long ranges.
9. Rate limiting is in-process (per API replica) plus nginx limits.
10. Reverse DNS on Top Destinations is an on-demand PTR lookup from the SIEM host, not FortiGate data.
11. "New domain" detection needs `learning_days` (default 3) of DNS history before it fires.
12. Policy analytics was validated with synthetic configurations and mocked API responses, and has **not** been tested against a live FortiGate's policy statistics. Check `/api/v2/monitor/firewall/policy` field names on your FortiOS build (the Policy Analytics page shows "counters not available" if the endpoint is missing or forbidden).
13. Shadow analysis covers IPv4/IPv6 firewall policies (`firewall/policy`). Proxy, multicast, local-in, central-NAT and policy-based-NGFW security policies are not analyzed. Interface pairs use zone expansion but not SD-WAN zone membership changes over time.
14. Counter usage is the sum of increments between SIEM snapshots inside the window. The first interval after collection starts is not counted, and a reboot between snapshots loses the hits from before the reboot in that interval.
16. Behaviour rules need history: new-country/new-port wait for `learning_days` (3) of traffic; volume baselines need 48 h of per-host hourly data. Beaconing excludes ports 53/123/443 by default (tunable) because update checks and agents beacon legitimately.
17. Impossible travel without GeoIP coordinates uses country centroids (marked "approximate"); shared VPN exits and proxies cause false positives.
18. Threat-intel matching applies to events ingested after an indicator is loaded (≤5 min); use Hunt for earlier events. abuse.ch withdrew the public URLhaus host file; it is disabled automatically on existing installs.
19. Compliance statuses are evidence support only, not an audit; NTP and other host-level controls are marked "manual".
20. Notifications to Teams use the Workflows webhook (adaptive card); legacy Office 365 connector URLs may stop working per Microsoft's retirement schedule.
21. Reports are HTML (print to PDF from the browser); there is no server-side PDF renderer.
15. Log matches before a policy ID was reused are attributed using `poluuid`. Logs that lack a UUID are only counted after the current UUID was first observed.
