# Deployment and Rollback Guide — modernization pass

This guide covers deploying the 2026-11-02 changes with the existing `scripts/deploy.sh` (rsync + `docker compose`) to the current host. Nothing in this pass changes published ports, credentials or the database contents.

## 1. What changes at deploy time

| Change | Effect on the running system | Action needed |
|---|---|---|
| Migration `0027` (12 indexes, `CREATE INDEX CONCURRENTLY`) | Runs in the `migrate` service before the API starts. Tables stay readable and writable. Build time grows with table size; `alerts` and `switch_events` are the largest | None. Expect `migrate` to take longer on a large database |
| New named volume `deadletter` on `syslog` and `worker` | Created empty on first `up` | Add it to your backup and retention scope (it may hold raw events) |
| PostgreSQL pool budget (about 180 → 82 peak) | Fewer idle connections. Requests wait up to 30 s for a free connection instead of failing with "too many clients" | If you run more API workers or raise poll concurrency, recheck §3 |
| ClickHouse client pool (4 per process) | Up to 4 concurrent ClickHouse requests per process instead of 1 | Watch ClickHouse CPU right after deploy; lower `CLICKHOUSE_POOL_SIZE` if needed |
| Ingestion backpressure and dead-letter | During a ClickHouse outage the relay's disk spool grows instead of `syslog` memory; poison chunks go to the spool | Monitor `dead_lettered`, `insert_failures` and `dropped_buffer_full` in the `syslog counters` log lines |
| `/api/metrics` (admin only), `X-Request-ID` on responses, access-log lines | More log lines (one per API request; health checks excluded) | Check log shipping volume |
| Rule cadence: `dns_spike` and `new_domain` run every 10 min | Fewer ClickHouse scans; the same coverage | None |
| Firewall polling backoff | An unreachable FortiGate is polled less often (up to every 15 min) until it answers again | None. Recovery resets on the next successful poll |

## 2. Steps

1. **Back up first.** The fixed async `backup.sh` doesn't hit the 300 s client timeout:
   ```bash
   ssh siem@10.200.64.58 'cd ~/fortisiem && ./scripts/backup.sh'
   ```
2. **Dry run:**
   ```bash
   ./scripts/deploy.sh
   ```
   Review the file list. The expected additions:
   - `backend/app/observability.py`
   - `backend/app/ingest/deadletter.py`
   - `backend/migrations/versions/0027_query_indexes.py`
   - `backend/tools/bench_api.py`
   - `frontend/src/lib/echarts.ts`
   - `.github/workflows/ci.yml`
   - the `docs/*.md` reports
3. **Deploy** (take the backup in step 1 first, or let the script take it):
   ```bash
   ./scripts/deploy.sh --apply
   ```
4. **Verify:**
   ```bash
   ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose ps && docker compose logs --no-color migrate | tail -5'
   ```
   ```bash
   ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose exec -T postgres sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -Atc \"select version_num from alembic_version; select indexrelid::regclass, indisvalid from pg_index where indexrelid::regclass::text like '"'"'ix_%'"'"' and not indisvalid\""'
   ```
   The second command should print `0027` and no invalid indexes.
   ```bash
   curl -sk -D - -o /dev/null https://10.200.64.58/api/health | grep -i x-request-id
   ```
   Then load the dashboard. Its first load should fetch a small `index-*.js`, followed by page chunks.

## 3. Connection budget (PostgreSQL `max_connections=100`)

| Process | Peak connections |
|---|---|
| API: 2 uvicorn workers × (`DB_POOL_SIZE` 4 + `DB_MAX_OVERFLOW` 4) | 16 |
| Worker: `WORKER_POLL_CONCURRENCY` (20) + `SWITCH_MAX_CONCURRENT_POLLS` (16) + 6 | 42 |
| Syslog: receiver 8 + 4 parsers × 2 | 16 |
| Traps | 8 |
| **Total** | **82** |

`migrate` exits before the others start. If you raise any of these limits, keep the total under 100, or raise PostgreSQL's `max_connections`. Raising `max_connections` means adding `command: ["postgres", "-c", "max_connections=150"]` to the `postgres` service; plan memory before doing so.

## 4. Rollback

The code and the index migration are independent and can each be rolled back.

1. **Code only (keep the indexes):** the indexes are harmless to older code. Redeploy the previous tree:
   ```bash
   git -C ~/Desktop/claude/fortisiem worktree add /tmp/sentinel-rollback checkpoint/pre-modernization-20261102
   ```
   Then run `./scripts/deploy.sh --apply` from `/tmp/sentinel-rollback`, or check out the checkpoint branch locally. Remove the worktree afterwards:
   ```bash
   git -C ~/Desktop/claude/fortisiem worktree remove /tmp/sentinel-rollback
   ```
2. **Indexes too:** downgrade *before* redeploying the old code, because the old code has no `0027` file:
   ```bash
   ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose run --rm migrate alembic downgrade 0026'
   ```
   This drops exactly the 12 indexes (`DROP INDEX CONCURRENTLY IF EXISTS`). No table data is touched.
3. **Dead-letter volume:** first check that it's empty:
   ```bash
   ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose run --rm --no-deps worker python -m app.ingest.deadletter list'
   ```
   If it isn't empty, replay it before rolling back. The volume can stay; old code ignores it.
4. **Database restore:** only needed if something unrelated goes wrong. Use `scripts/restore.sh <timestamp>` with the backup from step 1.

## 5. Operating the dead-letter spool

```bash
ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose exec -T syslog python -m app.ingest.deadletter list'
```

```bash
ssh siem@10.200.64.58 'cd ~/fortisiem && docker compose exec -T syslog python -m app.ingest.deadletter replay'
```

A file is deleted only after all of its events insert successfully. A file that ClickHouse still rejects stays in place, and its error is printed. The usual cause is a device clock that is years off; fix the source and replay.
