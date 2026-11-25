#!/usr/bin/env bash
# Backs up PostgreSQL (pg_dump) and ClickHouse (native BACKUP to a local File disk path) into ./backups/<timestamp>.
# The secrets (./secrets, in particular token_encryption_key) are NOT included; back them up separately (a vault).
set -euo pipefail
umask 077  # dumps hold password hashes and encrypted API tokens: owner-only
cd "$(dirname "$0")/.."
# shellcheck source=lib-env.sh
source scripts/lib-env.sh
POSTGRES_USER=$(envval POSTGRES_USER); POSTGRES_DB=$(envval POSTGRES_DB); CLICKHOUSE_DB=$(envval CLICKHOUSE_DB)
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="backups/$TS"; mkdir -p "$OUT" backups/clickhouse
echo "[backup] postgres -> $OUT/postgres.dump"
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$OUT/postgres.dump"
echo "[backup] clickhouse -> backups/clickhouse/$TS.zip"
# the ClickHouse server writes the archive as its own user (uid 101), not as the host user owning ./backups;
# group = this host user so the archives stay readable here, and nobody else gets access
docker compose exec -T clickhouse sh -c "chown clickhouse:$(id -g) /backups && chmod 2770 /backups"
ch() { chq "$1"; }   # password stays inside the clickhouse container (lib-env.sh)
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
chmod 700 backups "$OUT"

# Optional encryption to a public key (security/PRODUCTION_DEPLOYMENT.md, "Backups"): with BACKUP_GPG_RECIPIENT set in
# .env (a key imported with `gpg --import`), both files are encrypted and the plaintext removed. The server holds only
# the public key, so a copied backup is unreadable without the private key, which is kept offline.
RCPT=$(envval BACKUP_GPG_RECIPIENT)
if [ -n "$RCPT" ]; then
  for f in "$OUT/postgres.dump" "backups/clickhouse/$TS.zip"; do
    gpg --batch --yes --trust-model always --recipient "$RCPT" --output "$f.gpg" --encrypt "$f"
    rm -f "$f"
  done
  echo "[backup] encrypted for $RCPT"
else
  echo "[backup] WARNING: not encrypted (set BACKUP_GPG_RECIPIENT in .env); copy it only to storage you would trust with the database" >&2
fi

# retention: keep BACKUP_KEEP_DAYS (default 14) days of local backups; older ones are removed (copies elsewhere are not)
KEEP=$(envval BACKUP_KEEP_DAYS); KEEP=${KEEP:-14}
[[ "$KEEP" =~ ^[0-9]+$ ]] && [ "$KEEP" -ge 1 ] || { echo "[backup] BACKUP_KEEP_DAYS must be a positive number" >&2; exit 1; }
find backups -mindepth 1 -maxdepth 1 -type d -name '20*Z' -mtime +"$KEEP" -exec rm -rf {} +
find backups/clickhouse -maxdepth 1 -type f -name '20*Z.zip*' -mtime +"$KEEP" -delete 2>/dev/null || true
echo "[backup] done: $OUT (+ backups/clickhouse/$TS.zip${RCPT:+.gpg}); kept the last $KEEP days"
