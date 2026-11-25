#!/usr/bin/env bash
# Gives the services their own least-privilege ClickHouse account instead of the admin (security/SECRETS_MANAGEMENT.md,
# "Database accounts"). The account can read and write the application database (including the schema changes the
# migrations make) and read the system tables the app uses. It cannot create or drop databases, manage users, run
# SYSTEM commands, or use table functions that reach files, URLs, other servers or S3 (file(), url(), remote(), s3()),
# so an injected query cannot be turned into a file read or a request to another host. Idempotent; never prints the password.
#   ./scripts/create-clickhouse-app-user.sh [user]        default user: siem_ch_app
# Needs CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 on the clickhouse service (docker-compose.yml) so the admin can manage users.
# Afterwards: docker compose up -d   (the services reconnect as the new account).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib-env.sh
source scripts/lib-env.sh
U="${1:-siem_ch_app}"
[[ "$U" =~ ^[a-z_][a-z0-9_]{2,30}$ ]] || { echo "invalid user name" >&2; exit 1; }
ADMIN=$(envval CLICKHOUSE_USER); DB=$(envval CLICKHOUSE_DB)
[ "$U" != "$ADMIN" ] || { echo "the app account must differ from CLICKHOUSE_USER (the admin)" >&2; exit 1; }
[[ "$DB" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "unexpected CLICKHOUSE_DB" >&2; exit 1; }
umask 077
new=$(openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40)
# only the SHA-256 of the password reaches ClickHouse (and so its query log); the password itself goes to the secret file
if command -v sha256sum >/dev/null; then hash=$(printf '%s' "$new" | sha256sum | cut -d' ' -f1)
else hash=$(printf '%s' "$new" | shasum -a 256 | cut -d' ' -f1); fi
chq "CREATE USER IF NOT EXISTS $U IDENTIFIED WITH sha256_hash BY '$hash'"
chq "ALTER USER $U IDENTIFIED WITH sha256_hash BY '$hash'"
chq "REVOKE ALL ON *.* FROM $U"
chq "GRANT SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE, SHOW TABLES, SHOW COLUMNS ON $DB.* TO $U"
chq "GRANT SELECT ON system.parts TO $U"
chq "GRANT SELECT ON system.tables TO $U"
printf '%s' "$new" > secrets/clickhouse_app_password.new && chmod 444 secrets/clickhouse_app_password.new \
  && mv secrets/clickhouse_app_password.new secrets/clickhouse_app_password
if grep -q '^CLICKHOUSE_APP_USER=' .env; then sed -i.tmp "s/^CLICKHOUSE_APP_USER=.*/CLICKHOUSE_APP_USER=$U/" .env && rm -f .env.tmp
else echo "CLICKHOUSE_APP_USER=$U" >> .env; fi
echo "[clickhouse-app-user] $U can use $DB only (no user management, SYSTEM, file/url/remote/s3); secrets/clickhouse_app_password updated."
echo "[clickhouse-app-user] apply with: docker compose up -d   (services reconnect as $U)"
