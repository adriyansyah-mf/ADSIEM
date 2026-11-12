#!/bin/sh
# Scheduled backups (docker-compose.yml, backup service).
#
# - Postgres: pg_dump -Fc every BACKUP_INTERVAL_HOURS into /backups/postgres,
#   keeping the newest BACKUP_KEEP dumps. A dump is written to a .partial file
#   and renamed only when pg_dump succeeded, so a half-written file never looks
#   like a backup.
# - Elasticsearch: the snapshots themselves are taken by Elasticsearch's own
#   SLM policy (worker/worker/es_snapshots.py). This script only makes sure the
#   shared snapshot directory is writable by the elasticsearch user (uid 1000).
#
# Restore: docs/operations/backup-restore.md
set -eu

DUMPS=/backups/postgres
SNAPSHOTS=/backups/elasticsearch
INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
KEEP="${BACKUP_KEEP:-14}"

mkdir -p "$DUMPS" "$SNAPSHOTS"
chown 1000:0 "$SNAPSHOTS"
chmod 0770 "$SNAPSHOTS"

dump_once() {
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    target="$DUMPS/adsiem-$stamp.dump"
    if pg_dump -Fc --no-owner --file "$target.partial"; then
        mv "$target.partial" "$target"
        echo "backup.sh: postgres dump $target ($(du -h "$target" | cut -f1))"
        # keep the newest $KEEP dumps
        ls -1t "$DUMPS"/adsiem-*.dump 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
            rm -f "$old" && echo "backup.sh: removed old dump $old"
        done
        date -u +%s > "$DUMPS/.last-success"
    else
        rm -f "$target.partial"
        echo "backup.sh: postgres dump FAILED" >&2
        return 1
    fi
}

if [ "${1:-}" = "--once" ]; then
    dump_once
    exit $?
fi

until pg_isready -q; do sleep 5; done
while true; do
    dump_once || true  # a failed run is logged; the next interval retries
    sleep "$((INTERVAL_HOURS * 3600))"
done
