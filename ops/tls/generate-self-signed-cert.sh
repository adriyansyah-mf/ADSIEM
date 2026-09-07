#!/usr/bin/env bash
set -euo pipefail

# Generates a self-signed TLS cert/key for nginx into nginx/certs/, used by
# nginx/nginx.prod.conf until a real domain + CA-issued (e.g. Let's Encrypt)
# certificate replaces it. Safe to re-run: overwrites any existing cert/key.
#
# Usage: ops/tls/generate-self-signed-cert.sh [common_name] [days]
#   common_name defaults to "localhost"
#   days        defaults to 825 (~2.25 years, under browsers' max cert lifetime)

cn="${1:-localhost}"
days="${2:-825}"
out_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/nginx/certs"
mkdir -p "$out_dir"

openssl req -x509 -nodes -newkey rsa:2048 -days "$days" \
  -keyout "$out_dir/key.pem" -out "$out_dir/cert.pem" \
  -subj "/C=ID/ST=NA/L=NA/O=AD-SIEM/OU=SOC/CN=${cn}" \
  -addext "subjectAltName=DNS:${cn},DNS:*.${cn},IP:127.0.0.1"

chmod 644 "$out_dir/cert.pem"
chmod 600 "$out_dir/key.pem"

printf 'cert=%s\nkey=%s\n' "$out_dir/cert.pem" "$out_dir/key.pem"
printf 'Restart nginx to pick it up: docker compose up -d --no-deps nginx\n'
