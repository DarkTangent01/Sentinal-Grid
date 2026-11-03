#!/usr/bin/env bash
# New installation: creates ./secrets/<name> files with strong random values (docs/SECRET_MANAGEMENT.md) and .env from
# .env.example. Existing secret files are never overwritten. Nothing secret is printed.
# Existing installation whose .env still holds secrets: run scripts/migrate-secrets.sh instead.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
chmod 600 .env
if grep -Eq '^(POSTGRES_PASSWORD|CLICKHOUSE_PASSWORD|SECRET_KEY|TOKEN_ENCRYPTION_KEY|BOOTSTRAP_ADMIN_PASSWORD|ANTHROPIC_API_KEY)=.' .env; then
  echo "[gen-secrets] .env still contains secrets: run ./scripts/migrate-secrets.sh to move them into ./secrets" >&2
  exit 1
fi
umask 077
mkdir -p secrets && chmod 700 secrets
rand() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40; }
fernet() { openssl rand -base64 32 | tr '+/' '-_'; }
put() {  # name generator
  local f="secrets/$1"
  if [ -s "$f" ] || { [ -e "$f" ] && [ "$2" = "empty" ]; }; then echo "[gen-secrets] keep    $f"; return; fi
  case "$2" in
    rand) rand > "$f" ;;
    fernet) fernet > "$f" ;;
    empty) : > "$f" ;;
    copy:*) cp "secrets/${2#copy:}" "$f" ;;
  esac
  # 0444: the containers run as different users (app uid 10001, postgres 70, clickhouse 101) and plain Compose bind-mounts
  # the host file as is; the 0700 directory keeps other host users out
  chmod 444 "$f"
  echo "[gen-secrets] created $f"
}
put postgres_password rand
put db_app_password copy:postgres_password     # until scripts/create-app-db-role.sh gives the services their own role
put clickhouse_password rand
put secret_key rand
put token_encryption_key fernet
put token_encryption_key_previous empty
put bootstrap_admin_password rand
put anthropic_api_key empty
echo "[gen-secrets] done. The first admin's password is in secrets/bootstrap_admin_password (read it there; it is not printed)."
echo "[gen-secrets] Back up secrets/token_encryption_key separately from database backups: stored device credentials need it."
