#!/usr/bin/env bash
# Clear stale UDP syslog connection-tracking entries on this host (see deploy/ingress/fix-conntrack.sh).
# Run after the ingress container is (re)created, e.g. after a reboot if a UDP firewall's logs do not resume.
set -euo pipefail
cd "$(dirname "$0")/.."
ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose ps -q ingress)")
docker run --rm --net=host --cap-drop=ALL --cap-add=NET_ADMIN --user root --entrypoint /usr/local/bin/fix-conntrack.sh \
  fortisiem-ingress:1.0.0 "$ip"
