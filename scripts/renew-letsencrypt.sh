#!/bin/sh
# Renew the Let's Encrypt cert nginx serves for the public domain, then reload
# nginx so it picks the new files up (certs are loaded at start/reload only).
#
# certbot only renews within 30 days of expiry, so running this daily is cheap.
# Cron (as a user in the docker group):
#   17 3 * * * /opt/ADSIEM/scripts/renew-letsencrypt.sh >> $HOME/renew-letsencrypt.log 2>&1
#
# First issuance (once, with nginx already serving /.well-known/acme-challenge/):
#   docker run --rm -v "$ROOT/nginx/certs/letsencrypt:/etc/letsencrypt" \
#     -v "$ROOT/nginx/acme:/var/www/certbot" certbot/certbot:v3.0.1 certonly \
#     --webroot -w /var/www/certbot -d adsiem.my.id --agree-tos \
#     --register-unsafely-without-email --non-interactive
set -eu

ROOT="${ADSIEM_ROOT:-/opt/ADSIEM}"
NGINX_CONTAINER="${NGINX_CONTAINER:-siem-platform-nginx-1}"
PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

echo "== $(date -Is) renew"
docker run --rm \
  -v "$ROOT/nginx/certs/letsencrypt:/etc/letsencrypt" \
  -v "$ROOT/nginx/acme:/var/www/certbot" \
  certbot/certbot:v3.0.1 renew --webroot -w /var/www/certbot --non-interactive --quiet

# Reload only if the config still validates; a failed reload keeps the old certs.
docker exec "$NGINX_CONTAINER" nginx -t -q && docker exec "$NGINX_CONTAINER" nginx -s reload
echo "== $(date -Is) done"
