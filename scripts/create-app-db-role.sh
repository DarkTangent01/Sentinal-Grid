#!/usr/bin/env bash
# Gives the services their own PostgreSQL role instead of the superuser (docs/SECRET_MANAGEMENT.md, "Database accounts").
# The role owns the application schema (so migrations still work) but is not a superuser: it cannot read other
# databases' files, run COPY ... PROGRAM or create roles. Idempotent. Never prints the password.
#   ./scripts/create-app-db-role.sh [role]        default role: siem_app
# Afterwards set POSTGRES_APP_USER=<role> in .env and run `docker compose up -d`.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib-env.sh
source scripts/lib-env.sh
ROLE="${1:-siem_app}"
[[ "$ROLE" =~ ^[a-z_][a-z0-9_]{2,30}$ ]] || { echo "invalid role name" >&2; exit 1; }
SU=$(envval POSTGRES_USER); DB=$(envval POSTGRES_DB)
[ "$ROLE" != "$SU" ] || { echo "the app role must differ from POSTGRES_USER" >&2; exit 1; }
umask 077
new=$(openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40)
# the password travels on stdin (printf is a shell builtin: no process argument shows it), never on a command line
{ printf "\\set pw '%s'\n" "$new"; cat <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'role', :'pw') \gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'db', :'role') \gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'role') \gexec
-- every table, sequence and view in public (the bootstrap superuser cannot use REASSIGN OWNED)
SELECT format('ALTER TABLE public.%I OWNER TO %I', tablename, :'role') FROM pg_tables WHERE schemaname = 'public' \gexec
SELECT format('ALTER SEQUENCE public.%I OWNER TO %I', sequencename, :'role') FROM pg_sequences WHERE schemaname = 'public' \gexec
SELECT format('ALTER VIEW public.%I OWNER TO %I', viewname, :'role') FROM pg_views WHERE schemaname = 'public' \gexec
SELECT format('ALTER TYPE public.%I OWNER TO %I', t.typname, :'role') FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'public' AND t.typtype = 'e' \gexec
SQL
} | docker compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U "$SU" -d "$DB" -v role="$ROLE" -v db="$DB"
printf '%s' "$new" > secrets/db_app_password.new && chmod 444 secrets/db_app_password.new && mv secrets/db_app_password.new secrets/db_app_password
if grep -q '^POSTGRES_APP_USER=' .env; then sed -i.tmp "s/^POSTGRES_APP_USER=.*/POSTGRES_APP_USER=$ROLE/" .env && rm -f .env.tmp
else echo "POSTGRES_APP_USER=$ROLE" >> .env; fi
echo "[app-db-role] $ROLE owns the schema; secrets/db_app_password updated; POSTGRES_APP_USER=$ROLE set in .env."
echo "[app-db-role] apply with: docker compose up -d   (services reconnect as $ROLE)"
