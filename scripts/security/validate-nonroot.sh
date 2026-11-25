#!/usr/bin/env bash
# No application process runs as uid 0. Usage:
#   ./validate-nonroot.sh compose [project]     running containers (CLI=podman for Podman)
#   ./validate-nonroot.sh k8s [namespace]       running pods
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-compose}" in
  compose) python3 container_audit.py --cli "${CLI:-docker}" --only nonroot ${2:+--project "$2"} ;;
  k8s) python3 k8s_audit.py --live --namespace "${2:-sentinel}" --only nonroot ;;
  *) echo "usage: $0 compose|k8s [project|namespace]" >&2; exit 2 ;;
esac
