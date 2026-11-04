#!/bin/sh
# Download the GeoLite2 City + ASN databases into ./mmdb (mounted at /app/mmdb
# by server-api and worker). Source: https://github.com/P3TERX/GeoLite.mmdb,
# a mirror of MaxMind GeoLite2 refreshed every few days.
#
# Docker runs this automatically: the `geoip-init` service in docker-compose.yml
# downloads on first start and refreshes files older than GEOIP_MAX_AGE_DAYS.
# Manual use:
#   ./scripts/update-geoip.sh            # force a fresh download into ./mmdb
#   ./scripts/update-geoip.sh /opt/mmdb  # elsewhere
#
# Environment:
#   GEOIP_MAX_AGE_DAYS  only download files that are missing or older than this
#                       many days (unset = always download; 0 = only if missing)
#   GEOIP_SOFT_FAIL=1   warn and exit 0 on failure, so an offline host still boots
#   GEOIP_MIRROR        base URL holding GeoLite2-City.mmdb / GeoLite2-ASN.mmdb
#
# GeoLite2 data is (c) MaxMind, licensed CC BY-SA 4.0.
set -eu

DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/mmdb}"
BASE="${GEOIP_MIRROR:-https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download}"
MAX_AGE="${GEOIP_MAX_AGE_DAYS:-}"
SOFT="${GEOIP_SOFT_FAIL:-0}"

fail() {
  echo "geoip: $*" >&2
  if [ "$SOFT" = "1" ]; then
    echo "geoip: continuing without fresh GeoIP data (attack map and IP geolocation stay empty until it downloads)" >&2
    exit 0
  fi
  exit 1
}

needs_download() {
  [ -s "$1" ] || return 0                     # missing or empty
  [ -n "$MAX_AGE" ] || return 0               # no age policy: always refresh
  [ "$MAX_AGE" -gt 0 ] 2>/dev/null || return 1
  [ -n "$(find "$1" -mtime +"$MAX_AGE" 2>/dev/null)" ]
}

mkdir -p "$DEST" || fail "cannot create $DEST"
[ -w "$DEST" ] || fail "$DEST is not writable (docker may have created it as root): sudo chown \"\$USER\" \"$DEST\""

for f in GeoLite2-City.mmdb GeoLite2-ASN.mmdb; do
  target="$DEST/$f"
  if ! needs_download "$target"; then
    echo "geoip: $f is present and current, skipping"
    continue
  fi
  tmp="$(mktemp "$DEST/.$f.XXXXXX")" || fail "cannot create a temp file in $DEST"
  echo "geoip: downloading $f ..."
  if ! curl -fsSL --retry 3 --connect-timeout 20 --max-time 600 -o "$tmp" "$BASE/$f"; then
    rm -f "$tmp"
    fail "download of $f failed"
  fi
  # Every .mmdb ends with a metadata section introduced by "MaxMind.com", and
  # real databases are megabytes (an error page is not). Keep only letters and
  # dots before grepping: busybox grep can't match inside binary data.
  size=$(wc -c < "$tmp")
  if [ "$size" -lt 1000000 ] || ! tail -c 131072 "$tmp" | tr -dc 'A-Za-z.' | grep -q 'MaxMind.com'; then
    rm -f "$tmp"
    fail "$f does not look like a MaxMind database; keeping the existing file"
  fi
  chmod 644 "$tmp"
  mv -f "$tmp" "$target"
  echo "geoip: $f -> $target ($(du -h "$target" | cut -f1))"
done

echo "geoip: done"
