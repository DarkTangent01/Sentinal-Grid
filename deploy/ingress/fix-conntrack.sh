#!/bin/sh
# Drop UDP syslog connection-tracking entries that are not forwarded to the ingress container.
# A busy UDP sender (fixed source port) that hit port 514 while it was unmapped keeps an untranslated entry alive
# forever, black-holing its logs. Deleting a UDP entry is harmless: the next packet creates a correct one.
# Run on the host network with NET_ADMIN:  scripts/fix-syslog-conntrack.sh
set -eu
INGRESS_IP="${1:?ingress container IP}"
conntrack -L -p udp --orig-port-dst 514 2>/dev/null | while read -r line; do
  case "$line" in
    *"src=$INGRESS_IP "*) ;;  # reply comes from the ingress: correctly forwarded
    *) src=$(echo "$line" | awk '{for (i = 1; i <= NF; i++) { if ($i ~ /^src=/ && s == "") s = substr($i, 5); if ($i ~ /^sport=/ && p == "") p = substr($i, 7) } print s, p}')
       set -- $src
       [ -n "${1:-}" ] && conntrack -D -p udp --orig-src "$1" --orig-port-src "$2" --orig-port-dst 514 >/dev/null 2>&1 && echo "cleared stale entry for $1:$2" ;;
  esac
done
exit 0
