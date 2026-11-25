#!/usr/bin/env bash
# Runtime audit of the running containers (read-only). Usage: ./docker-security-audit.sh [compose-project]
# PASS / FAIL / WARN per check; exit 1 on FAIL. Also checks the Compose file statically (policy tests) when run from a checkout.
set -euo pipefail
cd "$(dirname "$0")"
CLI="${CLI:-docker}"
python3 container_audit.py --cli "$CLI" ${1:+--project "$1"}
