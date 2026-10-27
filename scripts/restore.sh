#!/usr/bin/env bash
# Restores a backup created by backup.sh:  ./scripts/restore.sh <timestamp>
# Stops api/worker/syslog during restore. Requires the same TOKEN_ENCRYPTION_KEY to use stored API tokens.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
TS="${1:?usage: restore.sh <timestamp>}"
[ -f "backups/$TS/postgres.dump" ] || { echo "backup backups/$TS not found"; exit 1; }
read -r -p "This REPLACES current data with backup $TS. Type 'restore' to continue: " ok
[ "$ok" = "restore" ] || exit 1
docker compose stop api worker syslog
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists < "backups/$TS/postgres.dump"
docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "DROP DATABASE IF EXISTS $CLICKHOUSE_DB SYNC"
docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "RESTORE DATABASE $CLICKHOUSE_DB FROM File('/backups/$TS.zip')"
docker compose start api worker syslog
echo "[restore] done"
