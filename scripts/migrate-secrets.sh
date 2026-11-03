#!/usr/bin/env bash
# Existing installation: moves the secrets that older versions kept in .env into ./secrets/<name> files, then removes
# them from .env (docs/SECRET_MANAGEMENT.md). Idempotent; never prints a value.
#   ./scripts/migrate-secrets.sh            dry run: which secrets would move
#   ./scripts/migrate-secrets.sh --apply    write the files, back up .env (mode 600) and strip the secrets from it
# Then redeploy / `docker compose up -d`: the services read the files. Delete the .env backup once the stack is healthy,
# and rotate the secrets (docs/CREDENTIAL_ROTATION.md): until then they may still sit in older backups and in the
# metadata of containers created before the move.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "no .env here" >&2; exit 1; }
# shellcheck source=lib-env.sh
source scripts/lib-env.sh
APPLY="${1:-}"
# .env key → secret file
MAP=(POSTGRES_PASSWORD:postgres_password CLICKHOUSE_PASSWORD:clickhouse_password SECRET_KEY:secret_key
     TOKEN_ENCRYPTION_KEY:token_encryption_key BOOTSTRAP_ADMIN_PASSWORD:bootstrap_admin_password ANTHROPIC_API_KEY:anthropic_api_key)
umask 077
[ "$APPLY" = "--apply" ] && { mkdir -p secrets; chmod 700 secrets; }
moved=()
for pair in "${MAP[@]}"; do
  key="${pair%%:*}"; name="${pair##*:}"; f="secrets/$name"
  val=$(envval "$key")
  if [ -s "$f" ]; then
    echo "[migrate-secrets] $f exists, keeping it${val:+ (the $key value in .env will be removed)}"
  elif [ -n "$val" ] && [ "$val" != "__CHANGE_ME__" ]; then
    echo "[migrate-secrets] $key -> $f"
    [ "$APPLY" = "--apply" ] && { printf '%s' "$val" > "$f"; chmod 444 "$f"; }
  elif [ "$name" = bootstrap_admin_password ]; then
    # removed from .env after the first sign-in (as earlier docs advised); only used while no user exists, but required
    echo "[migrate-secrets] $key not set -> $f gets a new random value (not printed)"
    [ "$APPLY" = "--apply" ] && { openssl rand -hex 24 > "$f"; chmod 444 "$f"; }
  elif [ "$name" = anthropic_api_key ]; then
    echo "[migrate-secrets] $key not set -> $f will be empty (feature off)"
    [ "$APPLY" = "--apply" ] && [ ! -e "$f" ] && { : > "$f"; chmod 444 "$f"; }
  else
    echo "[migrate-secrets] ERROR: $key is not set in .env and $f does not exist; the services cannot start without it" >&2
    exit 1
  fi
  grep -Eq "^$key=" .env && moved+=("$key")
done
if [ "$APPLY" = "--apply" ]; then
  [ -e secrets/token_encryption_key_previous ] || { : > secrets/token_encryption_key_previous; chmod 444 secrets/token_encryption_key_previous; }
  # the services keep using the superuser until scripts/create-app-db-role.sh creates their own role
  [ -s secrets/db_app_password ] || { cp secrets/postgres_password secrets/db_app_password; chmod 444 secrets/db_app_password; }
  if [ "${#moved[@]}" -gt 0 ]; then
    bak=".env.pre-secrets.$(date -u +%Y%m%dT%H%M%SZ).bak"
    cp -p .env "$bak"; chmod 600 "$bak"
    pattern=$(IFS='|'; echo "${moved[*]}")
    grep -Ev "^($pattern)=" .env > .env.tmp && mv .env.tmp .env && chmod 600 .env
    echo "[migrate-secrets] removed from .env: ${moved[*]}  (backup: $bak, mode 600; delete it once the stack is healthy)"
  fi
  echo "[migrate-secrets] done. Now: docker compose up -d   (then rotate the moved secrets: docs/CREDENTIAL_ROTATION.md)"
else
  echo "[migrate-secrets] dry run; nothing changed. Re-run with --apply."
fi
