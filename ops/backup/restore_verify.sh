#!/usr/bin/env bash
set -euo pipefail

backup_file="${1:?usage: restore_verify.sh POSTGRES_DUMP [ES_SNAPSHOT] [--confirm]}"
es_snapshot="${2:-}"
confirm="${3:-}"
if [[ "$confirm" != "--confirm" ]]; then
  echo 'restore is destructive; pass --confirm explicitly' >&2
  exit 2
fi
sha256sum -c "$backup_file.sha256"
docker compose exec -T postgres pg_restore --clean --if-exists -U "${POSTGRES_USER:-soc}" -d "${POSTGRES_DB:-soc_platform}" < "$backup_file"
docker compose exec -T postgres psql -U "${POSTGRES_USER:-soc}" -d "${POSTGRES_DB:-soc_platform}" -Atc 'select count(*) from alerts' | awk '{print "restored_alert_count=" $1}'
if [[ -n "$es_snapshot" ]]; then
  docker compose exec -T elasticsearch curl -fsS -X POST "http://127.0.0.1:9200/_snapshot/adsiem_backup/$es_snapshot/_restore?wait_for_completion=true" \
    -H 'content-type: application/json' -d '{"include_global_state":false}' >/dev/null
  docker compose exec -T elasticsearch curl -fsS 'http://127.0.0.1:9200/_cluster/health' | tr -d '\n'
  printf '\nrestored_es_snapshot=%s\n' "$es_snapshot"
fi
