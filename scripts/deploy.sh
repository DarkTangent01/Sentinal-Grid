#!/usr/bin/env bash
# Syncs this checkout to the SIEM server with rsync, then rebuilds and restarts the stack there.
#   ./scripts/deploy.sh            dry run: lists what would be copied or deleted, changes nothing
#   ./scripts/deploy.sh --apply    backup on the server, sync, docker compose build, nginx -t, up -d
#   SKIP_BACKUP=1 ./scripts/deploy.sh --apply    same, without the backup (only right after a completed one)
# Override the target with DEPLOY_REMOTE=user@host DEPLOY_PATH=/path.
# The server keeps its own .env, certificates, GeoIP files and backups: they are excluded, so --delete never touches them.
set -euo pipefail
cd "$(dirname "$0")/.."

REMOTE="${DEPLOY_REMOTE:-siem@10.200.64.58}"
DEST="${DEPLOY_PATH:-/home/siem/fortisiem}"
EXCLUDES=(
  --exclude='.env' --exclude='.venv/' --exclude='node_modules/' --exclude='frontend/dist/' --exclude='backups/'
  --exclude='.dev/' --exclude='*.db' --exclude='__pycache__/' --exclude='.pytest_cache/' --exclude='.ruff_cache/'
  --exclude='.claude/' --exclude='.DS_Store' --exclude='frontend/tsconfig.tsbuildinfo'
  --exclude='deploy/certs/*.key' --exclude='deploy/certs/*.crt' --exclude='deploy/certs/fortigate-ca/*.pem'
  --exclude='deploy/geoip/*.mmdb' --exclude='docs/SECURITY_AUDIT_REPORT.md'
)
SSH=(ssh -o BatchMode=yes "$REMOTE")

sync() {  # $1: extra rsync flags
  # shellcheck disable=SC2086
  rsync -az --delete --itemize-changes $1 "${EXCLUDES[@]}" ./ "$REMOTE:$DEST/"
}

if [ "${1:-}" != "--apply" ]; then
  echo "[deploy] DRY RUN to $REMOTE:$DEST (nothing is changed). Lines starting with *deleting are removed on --apply."
  sync -n
  echo "[deploy] review the list above, then run: ./scripts/deploy.sh --apply"
  exit 0
fi

read -r -p "[deploy] sync to $REMOTE:$DEST and restart the SIEM there? type yes: " ok
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

if [ "${SKIP_BACKUP:-}" = "1" ]; then
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
echo "[deploy] building and restarting"
# One-time cutover to the syslog ingress: the old syslog container still publishes port 514, so it must release the port
# before the ingress can bind it. Later deploys leave the ingress running (its image does not change), which is what
# keeps log collection uninterrupted while the rest of the stack is replaced.
"${SSH[@]}" "cd '$DEST' && docker compose build && docker compose run --rm --no-deps web nginx -t \
  && if [ -z \"\$(docker compose ps -q ingress 2>/dev/null)\" ]; then echo '[deploy] first ingress start: stopping old syslog listener'; docker compose stop syslog; fi \
  && docker compose up -d && sleep 5 && ./scripts/fix-syslog-conntrack.sh && docker compose ps"
echo "[deploy] done. Check: docker compose logs --tail=50 migrate api  (on the server)"
