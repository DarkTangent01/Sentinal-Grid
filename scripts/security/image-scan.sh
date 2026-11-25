#!/usr/bin/env bash
# Vulnerability scan (HIGH / CRITICAL, fixable) and CycloneDX SBOM for the Sentinel images, with the same pinned Trivy as
# CI (.github/workflows/ci.yml). Usage: ./image-scan.sh [image ...]   (default: the four locally built images)
# Reports go to ./reports/. Exit 1 when a fixable HIGH / CRITICAL vulnerability is found.
set -euo pipefail
CLI="${CLI:-docker}"
TRIVY="aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
images=("$@"); [ ${#images[@]} -gt 0 ] || images=(fortisiem-backend:1.0.0 fortisiem-web:1.0.0 fortisiem-ingress:1.0.0 fortisiem-tacacs:1.0.0)
mkdir -p reports; rc=0
sock=/var/run/docker.sock; [ "$CLI" = podman ] && sock="$(podman info --format '{{.Host.RemoteSocket.Path}}' | sed 's#^unix://##')"
for img in "${images[@]}"; do
  name="$(echo "$img" | tr '/:@' '___')"
  echo "== $img"
  # the scanner gets the runtime socket read-only for the scan only; it is a short-lived tool container, never a service
  "$CLI" run --rm -v "$sock:/var/run/docker.sock:ro" -v "$PWD/reports:/reports" "$TRIVY" image --scanners vuln,secret \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table --output "/reports/trivy-$name.txt" "$img" || rc=1
  "$CLI" run --rm -v "$sock:/var/run/docker.sock:ro" -v "$PWD/reports:/reports" "$TRIVY" image --format cyclonedx \
    --output "/reports/sbom-$name.cdx.json" "$img" >/dev/null || echo "WARN  SBOM not generated for $img"
  tail -n 3 "reports/trivy-$name.txt" 2>/dev/null || true
done
[ $rc -eq 0 ] && echo "PASS  no fixable HIGH / CRITICAL vulnerability" || echo "FAIL  fixable HIGH / CRITICAL vulnerabilities: see reports/"
exit $rc
