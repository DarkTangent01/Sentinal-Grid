#!/usr/bin/env bash
# Backs up PostgreSQL (pg_dump) and ClickHouse (native BACKUP to a local File disk path) into ./backups/<timestamp>.
# TOKEN_ENCRYPTION_KEY is NOT included; store it separately (e.g. a secrets vault).
set -euo pipefail
umask 077  # dumps hold password hashes and encrypted API tokens: owner-only
cd "$(dirname "$0")/.."
source .env
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="backups/$TS"; mkdir -p "$OUT" backups/clickhouse
echo "[backup] postgres -> $OUT/postgres.dump"
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$OUT/postgres.dump"
echo "[backup] clickhouse -> backups/clickhouse/$TS.zip"
# the ClickHouse server writes the archive as its own user (uid 101), not as the host user owning ./backups;
# group = this host user so the archives stay readable here, and nobody else gets access
docker compose exec -T clickhouse sh -c "chown clickhouse:$(id -g) /backups && chmod 2770 /backups"
ch() { docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$1"; }
# ASYNC: a synchronous BACKUP of a large database outlives clickhouse-client's 300 s receive timeout
ID=$(ch "BACKUP DATABASE $CLICKHOUSE_DB TO File('/backups/$TS.zip') ASYNC" | cut -f1)
while :; do
  ST=$(ch "SELECT status FROM system.backups WHERE id = '$ID'" | tr -dc 'A-Z_')
  case "$ST" in
    BACKUP_CREATED) break ;;
    CREATING_BACKUP) echo "[backup] clickhouse still running: $(du -h "backups/clickhouse/$TS.zip" 2>/dev/null | cut -f1) written"; sleep 30 ;;
    *) echo "[backup] clickhouse backup failed ($ST): $(ch "SELECT substring(error, 1, 300) FROM system.backups WHERE id = '$ID'")" >&2
       exit 1 ;;
  esac
done
echo "$TS" > "$OUT/clickhouse_backup_name"
echo "[backup] done: $OUT (+ backups/clickhouse/$TS.zip)"
