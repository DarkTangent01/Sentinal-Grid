#!/usr/bin/env bash
# Roll one service back to the image it ran before its last deployment (kept on the server; nothing is rebuilt).
#   ./scripts/rollback.sh api | ui | worker | poller | access | syslog | traps | flows | ansible | edge | ingress | tacacs
#   ./scripts/rollback.sh --status          deployed versions, previous versions and container health
# Database migrations are never reversed: they are expand-only, so the previous version runs on the current schema
# (docs/rollback-guide.md). Override the server with DEPLOY_REMOTE=user@host DEPLOY_PATH=/path.
set -euo pipefail
REMOTE="${DEPLOY_REMOTE:-siem@10.200.64.58}"
DEST="${DEPLOY_PATH:-/home/siem/fortisiem}"
case "${1:-}" in
  ""|-h|--help) sed -n '2,7p' "$0"; exit 2;;
  --status) exec ssh -o BatchMode=yes "$REMOTE" "cd '$DEST' && ./scripts/release.sh status";;
  *[!a-z]*) echo "unknown service: $1" >&2; exit 2;;
esac
read -r -p "[rollback] roll $1 back to its previous version on $REMOTE? type yes: " ok
[ "$ok" = "yes" ] || { echo "aborted"; exit 1; }
exec ssh -o BatchMode=yes "$REMOTE" "cd '$DEST' && ./scripts/release.sh rollback '$1'"
