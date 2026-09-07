#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-backups/postgres}"
mkdir -p "$output_dir"
file="$output_dir/soc_platform-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T postgres pg_dump -Fc -U "${POSTGRES_USER:-soc}" -d "${POSTGRES_DB:-soc_platform}" > "$file"
sha256sum "$file" > "$file.sha256"
printf 'postgres_backup=%s\n' "$file"
