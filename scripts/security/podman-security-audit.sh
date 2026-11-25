#!/usr/bin/env bash
# Same audit with Podman. Usage: ./podman-security-audit.sh [compose-project]
set -euo pipefail
cd "$(dirname "$0")"
CLI=podman exec ./docker-security-audit.sh "$@"
