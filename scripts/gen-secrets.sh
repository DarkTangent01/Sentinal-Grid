#!/usr/bin/env bash
# Fills __CHANGE_ME__ placeholders in .env with strong random values.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
rand() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40; }
fernet() { openssl rand -base64 32 | tr '+/' '-_'; }
tmp=$(mktemp)
while IFS= read -r line; do
  case "$line" in
    TOKEN_ENCRYPTION_KEY=__CHANGE_ME__) echo "TOKEN_ENCRYPTION_KEY=$(fernet)";;
    *=__CHANGE_ME__) echo "${line%%=*}=$(rand)";;
    *) echo "$line";;
  esac
done < .env > "$tmp"
mv "$tmp" .env && chmod 600 .env
# the password is not echoed: terminal scrollback and CI logs keep it. Read it from .env (BOOTSTRAP_ADMIN_PASSWORD).
echo "Secrets written to .env (mode 600). The bootstrap admin password is BOOTSTRAP_ADMIN_PASSWORD in .env."
echo "Back up TOKEN_ENCRYPTION_KEY separately from database backups."
