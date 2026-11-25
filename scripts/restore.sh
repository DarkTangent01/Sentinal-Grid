#!/usr/bin/env bash
# Restores a backup created by backup.sh:  ./scripts/restore.sh <timestamp>
# Stops the app services during restore. Requires the same secrets/token_encryption_key to use stored credentials.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib-env.sh
source scripts/lib-env.sh
POSTGRES_USER=$(envval POSTGRES_USER); POSTGRES_DB=$(envval POSTGRES_DB); CLICKHOUSE_DB=$(envval CLICKHOUSE_DB)
TS="${1:?usage: restore.sh <timestamp>}"
if [ -f "backups/$TS/postgres.dump.gpg" ] || [ -f "backups/clickhouse/$TS.zip.gpg" ]; then
  # the private key is kept offline on purpose (backup.sh): decrypt on a trusted machine, then copy the plaintext here
  echo "backup $TS is encrypted: decrypt it first, e.g." >&2
  echo "  gpg --output backups/$TS/postgres.dump --decrypt backups/$TS/postgres.dump.gpg" >&2
  echo "  gpg --output backups/clickhouse/$TS.zip --decrypt backups/clickhouse/$TS.zip.gpg" >&2
  [ -f "backups/$TS/postgres.dump" ] && [ -f "backups/clickhouse/$TS.zip" ] || exit 1
fi
[ -f "backups/$TS/postgres.dump" ] || { echo "backup backups/$TS not found"; exit 1; }
[ -f "backups/clickhouse/$TS.zip" ] || { echo "ClickHouse archive backups/clickhouse/$TS.zip not found"; exit 1; }
read -r -p "This REPLACES current data with backup $TS. Type 'restore' to continue: " ok
[ "$ok" = "restore" ] || exit 1
docker compose stop api worker syslog traps
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists < "backups/$TS/postgres.dump"
chq "DROP DATABASE IF EXISTS $CLICKHOUSE_DB SYNC"
chq "RESTORE DATABASE $CLICKHOUSE_DB FROM File('/backups/$TS.zip')"
docker compose start api worker syslog traps
echo "[restore] done"
