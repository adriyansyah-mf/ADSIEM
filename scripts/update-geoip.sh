#!/usr/bin/env bash
# Download the GeoLite2 City + ASN databases into ./mmdb (mounted at /app/mmdb
# by server-api and worker). Source: https://github.com/P3TERX/GeoLite.mmdb,
# a mirror of MaxMind GeoLite2 refreshed every few days.
#
#   ./scripts/update-geoip.sh            # into ./mmdb
#   ./scripts/update-geoip.sh /opt/mmdb  # elsewhere
#
# Weekly refresh via cron:  0 4 * * 1  cd /path/to/ADSIEM && ./scripts/update-geoip.sh
# GeoLite2 data is (c) MaxMind, licensed CC BY-SA 4.0.
set -euo pipefail

DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/mmdb}"
BASE="${GEOIP_MIRROR:-https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download}"
FILES=(GeoLite2-City.mmdb GeoLite2-ASN.mmdb)

mkdir -p "$DEST"
if [ ! -w "$DEST" ]; then
  echo "error: $DEST is not writable (docker may have created it as root): sudo chown \"$USER\" \"$DEST\"" >&2
  exit 1
fi

for f in "${FILES[@]}"; do
  tmp="$(mktemp "$DEST/.$f.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  echo "downloading $f ..."
  curl -fsSL --retry 3 --connect-timeout 20 -o "$tmp" "$BASE/$f"
  # Every .mmdb ends with a metadata section introduced by this marker.
  if ! grep -aq 'MaxMind.com' "$tmp"; then
    echo "error: $f does not look like a MaxMind database; keeping the existing file" >&2
    exit 1
  fi
  chmod 644 "$tmp"
  mv -f "$tmp" "$DEST/$f"
  trap - EXIT
  echo "  -> $DEST/$f ($(du -h "$DEST/$f" | cut -f1))"
done

echo "done. Restart to load the new data: docker compose restart server-api worker"
