#!/usr/bin/env bash
# Kubernetes security audit. Usage:
#   ./kubernetes-security-audit.sh render <overlay>     static: kubectl kustomize k8s/overlays/<overlay>
#   ./kubernetes-security-audit.sh live [namespace]     the running cluster
# Production renders also require digest-pinned images.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$here/../.."
case "${1:-}" in
  render)
    ov="${2:?overlay: development|staging|production}"; dir="$(mktemp -d)"; out="$dir/rendered.yaml"; trap 'rm -f "$out"; rmdir "$dir"' EXIT
    kubectl kustomize "$root/k8s/overlays/$ov" > "$out"
    if command -v kubeconform >/dev/null; then kubeconform -strict -summary "$out"; else echo "WARN  kubeconform not installed: schema validation not tested"; fi
    python3 "$here/k8s_audit.py" --manifests "$out" $([ "$ov" = production ] && echo --require-digests) ;;
  live) python3 "$here/k8s_audit.py" --live --namespace "${2:-sentinel}" ;;
  *) echo "usage: $0 render <overlay> | live [namespace]" >&2; exit 2 ;;
esac
