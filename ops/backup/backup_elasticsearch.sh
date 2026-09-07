#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-backups/elasticsearch}"
mkdir -p "$output_dir"
repo="adsiem_backup"
if ! docker compose exec -T elasticsearch curl -fsS "http://127.0.0.1:9200/_snapshot/$repo" >/dev/null; then
  docker compose exec -T elasticsearch curl -fsS -X PUT "http://127.0.0.1:9200/_snapshot/$repo" \
    -H 'content-type: application/json' \
    -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/backup","compress":true}}' >/dev/null
fi
snapshot="snapshot-$(date -u +%Y%m%dt%H%M%S)-$$"
temp_file="$output_dir/.$snapshot.json.tmp"
docker compose exec -T elasticsearch curl -fsS -X PUT "http://127.0.0.1:9200/_snapshot/$repo/$snapshot?wait_for_completion=true" \
  -H 'content-type: application/json' \
  -d '{"include_global_state":true,"feature_states":[]}' > "$temp_file"
mv "$temp_file" "$output_dir/$snapshot.json"
sha256sum "$output_dir/$snapshot.json" > "$output_dir/$snapshot.json.sha256"
printf 'elasticsearch_snapshot=%s\n' "$snapshot"
