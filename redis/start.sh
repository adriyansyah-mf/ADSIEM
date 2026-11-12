#!/bin/sh
# Start Redis with AOF persistence and a memory cap (docker-compose.yml, redis).
#
# Turning on --appendonly on a volume that so far only has an RDB snapshot
# starts Redis with an EMPTY dataset: it loads the (new, empty) AOF and ignores
# dump.rdb. That would drop the queued logs and caches of every existing
# install on upgrade. So until the marker below exists, dump.rdb is the source
# of truth: load it without AOF, switch AOF on at runtime (which rewrites the
# loaded data into the AOF), check the rewrite succeeded, and only then write
# the marker. An interrupted conversion leaves no marker and simply runs again.
#
# The last step hands over to the image's own entrypoint, which owns /data and
# drops to the redis user, exactly as with the stock `redis-server` command.
set -eu

MARKER=/data/.adsiem-aof-ready
MAXMEMORY="${REDIS_MAXMEMORY:-1536mb}"

aof_rewrite_busy() {
    redis-cli info persistence | grep -Eq '^aof_rewrite_(in_progress|scheduled):1'
}

if [ ! -f "$MARKER" ]; then
    if [ -f /data/dump.rdb ]; then
        echo "redis/start.sh: converting the existing RDB snapshot to AOF"
        find /data \! -user redis -exec chown redis '{}' +
        rm -rf /data/appendonlydir  # leftovers of an interrupted conversion; dump.rdb is authoritative
        # same privilege drop as the image's docker-entrypoint.sh
        setpriv --reuid redis --regid redis --clear-groups \
            redis-server --appendonly no --daemonize yes --dir /data --bind 127.0.0.1
        # loading a large RDB answers LOADING until done; give up only if the server died
        until redis-cli ping 2>/dev/null | grep -q PONG; do
            pidof redis-server >/dev/null || { echo "redis/start.sh: temporary server exited"; exit 1; }
            sleep 0.5
        done
        redis-cli config set appendonly yes >/dev/null
        sleep 0.5
        while aof_rewrite_busy; do sleep 0.5; done
        if ! redis-cli info persistence | grep -q '^aof_last_bgrewrite_status:ok'; then
            echo "redis/start.sh: AOF rewrite failed; keeping dump.rdb and retrying on next start"
            redis-cli shutdown nosave >/dev/null 2>&1 || true
            exit 1
        fi
        redis-cli shutdown nosave >/dev/null 2>&1 || true
        while pidof redis-server >/dev/null; do sleep 0.2; done
    fi
    touch "$MARKER"
fi

exec docker-entrypoint.sh redis-server --dir /data \
    --appendonly yes --appendfsync everysec \
    --maxmemory "$MAXMEMORY" --maxmemory-policy noeviction
