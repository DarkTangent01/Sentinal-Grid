#!/usr/bin/env bash
# Post-deployment validation. Usage:
#   ./validate-deployment.sh compose [project]   Compose / Podman host (CLI=podman for Podman)
#   ./validate-deployment.sh k8s [namespace]     Kubernetes
# Health first, then the security audits. Exit 1 when anything FAILs.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; rc=0
case "${1:-compose}" in
  compose)
    CLI="${CLI:-docker}"
    bad=$("$CLI" ps --format '{{.Names}} {{.Status}}' | grep -E "unhealthy|Restarting|Exited" || true)
    if [ -z "$bad" ]; then echo "PASS  every container running and healthy"; else echo "FAIL  $bad"; rc=1; fi
    CLI="$CLI" "$here/docker-security-audit.sh" ${2:+"$2"} || rc=1 ;;
  k8s)
    NS="${2:-sentinel}"
    notready=$(kubectl -n "$NS" get pods --no-headers | awk '$3!="Running" && $3!="Completed"{print $1, $3}')
    if [ -z "$notready" ]; then echo "PASS  every pod running"; else echo "FAIL  $notready"; rc=1; fi
    kubectl -n "$NS" wait --for=condition=available deploy --all --timeout=60s >/dev/null && echo "PASS  deployments available" || { echo "FAIL  deployments not available"; rc=1; }
    "$here/kubernetes-security-audit.sh" live "$NS" || rc=1
    "$here/validate-network-policies.sh" "$NS" || rc=1 ;;
  *) echo "usage: $0 compose|k8s [project|namespace]" >&2; exit 2 ;;
esac
exit $rc
