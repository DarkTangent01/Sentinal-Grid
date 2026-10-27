#!/usr/bin/env bash
# Creates a temporary self-signed certificate for the web UI. Replace with a certificate from your internal CA.
set -euo pipefail
cd "$(dirname "$0")/.."
CN="${1:-siem.internal}"
mkdir -p deploy/certs
[ -f deploy/certs/siem.crt ] && { echo "deploy/certs/siem.crt already exists"; exit 0; }
openssl req -x509 -nodes -newkey rsa:3072 -days 365 -subj "/CN=${CN}" -addext "subjectAltName=DNS:${CN}" \
  -keyout deploy/certs/siem.key -out deploy/certs/siem.crt
chmod 600 deploy/certs/siem.key
echo "Self-signed certificate created for ${CN}. Replace it with an internally trusted certificate."
