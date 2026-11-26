#!/usr/bin/env bash
# Syncs this checkout to the Sentinel server with rsync, then deploys only what changed, service by service, with health
# checks and automatic rollback (scripts/release.sh on the server; docs/deployment-guide.md). Nothing else restarts.
#   ./scripts/deploy.sh                       dry run: lists what would be copied or deleted, changes nothing
#   ./scripts/deploy.sh --apply               sync, then deploy whatever changed ("auto")
#   ./scripts/deploy.sh --apply ui            the web UI only (no restart of anything; nginx keeps serving)
#   ./scripts/deploy.sh --apply api           the API only (rolling: no downtime)
#   ./scripts/deploy.sh --apply poller        pollers one by one; also: worker, access, syslog, traps, flows, ansible, edge,
#                                             ingress, tacacs, migrate, backend, all
#   options: --no-cache (rebuild images from scratch), --allow-destructive (accept a contracting migration, after a backup)
#   SKIP_BACKUP=1 ./scripts/deploy.sh --apply …   no backup first (a backup is only taken when the database may change)
#   ./scripts/rollback.sh <service>           previous image of one service, no rebuild
# Override the target with DEPLOY_REMOTE=user@host DEPLOY_PATH=/path.
# Only production files are copied (scripts/deploy-files.rsync). Secrets are never copied from here
# (security/SECRETS_MANAGEMENT.md).
set -euo pipefail
cd "$(dirname "$0")/.."

REMOTE="${DEPLOY_REMOTE:-siem@10.200.64.58}"
DEST="${DEPLOY_PATH:-/home/siem/fortisiem}"
# What the server receives: an allowlist (scripts/deploy-files.rsync) of what the stack needs to build and run plus the
# operational scripts. Docs, tests, CI, Kubernetes manifests and dev / lab tooling are never copied. The server keeps its
# own .env, ./secrets, backups, certificates and GeoIP files: they are excluded, so --delete never touches them
# (plain --delete only: never --delete-excluded, see the filter file).
FILTER=(--filter="merge scripts/deploy-files.rsync")
SSH=(ssh -n -o BatchMode=yes "$REMOTE")   # -n: remote commands must not swallow the answers piped to the prompts

sync() {  # $1: extra rsync flags
  # shellcheck disable=SC2086
  rsync -az --delete --itemize-changes $1 "${FILTER[@]}" ./ "$REMOTE:$DEST/"
}

APPLY=""; TARGETS=()
for a in "$@"; do case "$a" in --apply) APPLY=1;; *) TARGETS+=("$a");; esac; done
for a in "${TARGETS[@]:-}"; do
  case "$a" in ""|--no-cache|--allow-destructive|--force|auto|all|backend|migrate|api|poller|worker|access|syslog|traps|flows|ansible|ui|edge|ingress|tacacs) ;;
    *) echo "[deploy] unknown target or option: $a" >&2; exit 2;; esac
done

if [ -z "$APPLY" ]; then
  echo "[deploy] DRY RUN to $REMOTE:$DEST (nothing is changed). Lines starting with *deleting are removed on --apply."
  sync -n
  echo "[deploy] review the list above, then run: ./scripts/deploy.sh --apply"
  exit 0
fi

# Security gate (security/PRODUCTION_DEPLOYMENT.md): the static container / secrets policy tests must pass before anything
# leaves this machine: no secret in a service's environment or the images, scoped secret mounts, no privileged or
# socket-mounting container, no published database port, network segmentation. CI runs the full scanners as well.
if [ -x .venv/bin/python ]; then
  (cd backend && ../.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_secret_files.py >/dev/null) \
    || { echo "[deploy] container / secrets policy checks failed (cd backend && ../.venv/bin/python -m pytest tests/test_secret_files.py): not deploying" >&2; exit 1; }
  echo "[deploy] container / secrets policy checks passed"
else
  echo "[deploy] WARNING: .venv not found, policy checks skipped (create it as in README, Development)" >&2
fi

read -r -p "[deploy] sync to $REMOTE:$DEST and deploy ${TARGETS[*]:-what changed} there? type yes: " ok
[ "$ok" = "yes" ] || { echo "aborted"; exit 1; }

"${SSH[@]}" "test -f '$DEST/.env'" || {
  echo "[deploy] $DEST/.env is missing on the server. Create it there first (never copy it from here):"
  echo "         cd $DEST && ./scripts/gen-secrets.sh && ./scripts/gen-selfsigned-cert.sh"
  exit 1
}
if ! "${SSH[@]}" "grep -Eq '^WEB_BIND_IP=.+' '$DEST/.env' && grep -Eq '^SYSLOG_BIND_IP=.+' '$DEST/.env'"; then
  echo "[deploy] WARNING: WEB_BIND_IP / SYSLOG_BIND_IP are not set in the server .env; they now default to 127.0.0.1,"
  echo "         so the UI and syslog would not be reachable from the network. Set them to the server's interface IP."
  read -r -p "[deploy] continue anyway? type yes: " ok
  [ "$ok" = "yes" ] || exit 1
fi

# a backup only matters when the database may change: anything but UI / proxy / collector-only deployments
DB_SAFE=1
for a in "${TARGETS[@]:-auto}"; do case "$a" in ui|edge|ingress|tacacs|--*) ;; *) DB_SAFE="";; esac; done
if [ -n "$DB_SAFE" ]; then
  echo "[deploy] ${TARGETS[*]}: the database is not touched, no backup needed"
elif [ "${SKIP_BACKUP:-}" = "1" ]; then
  echo "[deploy] SKIP_BACKUP=1: no backup taken. Latest backups on the server:"
  "${SSH[@]}" "cd '$DEST' && ls -1t backups/clickhouse/*.zip 2>/dev/null | head -3"
elif "${SSH[@]}" "cd '$DEST' && docker compose ps -q postgres 2>/dev/null | grep -q ."; then
  echo "[deploy] backing up the running stack"
  "${SSH[@]}" "cd '$DEST' && ./scripts/backup.sh"
else
  echo "[deploy] postgres is not running on the server: no backup taken (first deploy?)"
fi

echo "[deploy] syncing"
sync ""

# secrets live in ./secrets on the server (file-mounted, never environment variables). First deploy after that change:
# move them out of the server's .env (scripts/migrate-secrets.sh), with consent.
SECRET_KEYS='^(POSTGRES_PASSWORD|CLICKHOUSE_PASSWORD|SECRET_KEY|TOKEN_ENCRYPTION_KEY|BOOTSTRAP_ADMIN_PASSWORD|ANTHROPIC_API_KEY)=.'
# a secret file added by a newer version (e.g. clickhouse_app_password) is derived from the existing ones; never printed
if "${SSH[@]}" "cd '$DEST' && test -s secrets/token_encryption_key && test -s secrets/db_app_password && ! test -s secrets/clickhouse_app_password"; then
  "${SSH[@]}" "cd '$DEST' && ./scripts/migrate-secrets.sh --apply" | grep -v ' -> \| keeping ' || true
fi
if ! "${SSH[@]}" "cd '$DEST' && test -s secrets/token_encryption_key && test -s secrets/db_app_password"; then
  echo "[deploy] the server has no ./secrets yet: its secrets are still in .env (visible via docker inspect)."
  "${SSH[@]}" "cd '$DEST' && ./scripts/migrate-secrets.sh"
  read -r -p "[deploy] move them into ./secrets on the server now (.env is backed up, mode 600)? type yes: " ok
  [ "$ok" = "yes" ] || { echo "[deploy] aborted before restarting anything; the old containers keep running"; exit 1; }
  "${SSH[@]}" "cd '$DEST' && ./scripts/migrate-secrets.sh --apply"
fi
if "${SSH[@]}" "grep -Eq '$SECRET_KEYS' '$DEST/.env'"; then
  echo "[deploy] the server .env still contains secrets; they would reach every container as environment variables."
  echo "         run on the server: ./scripts/migrate-secrets.sh --apply"
  exit 1
fi
# nginx runs as the owner of the TLS key (docker-compose.yml, web.user): record that uid once, never loosen the key's mode
"${SSH[@]}" "cd '$DEST' && { grep -q '^WEB_UID=' .env || echo \"WEB_UID=\$(stat -c %u deploy/certs/siem.key)\" >> .env; }"
# service-by-service deployment on the server: builds only changed images, health-gates every switch, rolls back on failure
# and leaves every other container (databases, collectors, the syslog ingress, the proxy) running
echo "[deploy] deploying on the server"
"${SSH[@]}" "cd '$DEST' && ./scripts/release.sh deploy ${TARGETS[*]:-auto}"
"${SSH[@]}" "cd '$DEST' && ./scripts/release.sh status"
echo "[deploy] done. History: ssh $REMOTE 'cd $DEST && ./scripts/release.sh history'   Rollback: ./scripts/rollback.sh <service>"
