# Backup and restore

ADSIEM keeps state in two places. Both are backed up into `BACKUP_DIR` (default
`./backups` next to `docker-compose.yml`):

| Store | Holds | Backed up by | Lands in |
|---|---|---|---|
| Postgres | agents, alerts, cases, rules, policies, users, settings | `backup` service: `pg_dump -Fc` every `BACKUP_INTERVAL_HOURS` (24), newest `BACKUP_KEEP` (14) kept | `BACKUP_DIR/postgres/adsiem-<UTC>.dump` |
| Elasticsearch | every ingested log (`logs`), alert IoCs (`alert_iocs`) | Elasticsearch's own SLM policy `adsiem-daily`, 01:30 UTC, kept `ES_SNAPSHOT_RETAIN_DAYS` (14) days | `BACKUP_DIR/elasticsearch` (an `fs` snapshot repository) |

Redis isn't backed up: it holds the in-flight queue and caches, and it persists
them with AOF (`redis/start.sh`).

**Copy `BACKUP_DIR` off the host.** Backups on the same disk survive a bad
upgrade or an accidental delete, but not a lost disk. Any file-level tool works
(rsync, restic, rclone to object storage). Elasticsearch snapshot files are
immutable once written, so incremental copies are cheap.

## Settings

| Variable | Default | |
|---|---|---|
| `BACKUP_DIR` | `./backups` | host directory for both |
| `BACKUP_INTERVAL_HOURS` | `24` | Postgres dump interval |
| `BACKUP_KEEP` | `14` | Postgres dumps kept |
| `ES_SNAPSHOT_SCHEDULE` (worker) | `0 30 1 * * ?` | SLM cron (UTC), before the daily retention purge |
| `ES_SNAPSHOT_RETAIN_DAYS` (worker) | `14` | snapshots expire after this many days (at least 3 kept) |
| `ES_SNAPSHOTS` (worker) | `on` | `off` stops the worker from (re)creating the policy |

The worker registers the repository and the policy at startup and again on
every daily maintenance run. A recreated cluster therefore gets them back, and
`maintenance_done` log lines report `snapshot_last_success` and
`snapshot_last_failure`. If the worker starts before the `backup` service has
made the snapshot directory writable (uid 1000), the first registration fails
with `es_snapshot_repository_unavailable` and the next maintenance run retries.

## Check the backups

```bash
ls -lt backups/postgres | head                       # newest dumps
cat backups/postgres/.last-success                   # epoch of the last good dump
docker compose logs backup | tail                    # dump results
docker compose exec elasticsearch curl -s localhost:9200/_slm/policy/adsiem-daily?pretty   # last_success / last_failure
docker compose exec elasticsearch curl -s 'localhost:9200/_snapshot/adsiem-backups/_all?pretty' | grep '"snapshot"'
```

Take one now (before an upgrade, for example):

```bash
docker compose exec backup sh /usr/local/bin/backup.sh --once
docker compose exec elasticsearch curl -s -XPOST localhost:9200/_slm/policy/adsiem-daily/_execute
```

## Restore Postgres

```bash
docker compose stop server-api worker   # nothing writes while restoring
DUMP=backups/postgres/adsiem-20261112T013000Z.dump      # pick one
docker compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" --if-exists soc_restore && createdb -U "$POSTGRES_USER" soc_restore'
docker compose exec -T postgres pg_restore -U soc -d soc_restore --no-owner < "$DUMP"
# check it, then swap: rename the live DB away and the restored one in
docker compose exec -T postgres psql -U soc -d postgres -c 'ALTER DATABASE soc_platform RENAME TO soc_platform_old' -c 'ALTER DATABASE soc_restore RENAME TO soc_platform'
docker compose start server-api worker
```

Restoring into a fresh database and renaming keeps the old one until you're
sure. Drop `soc_platform_old` afterwards.

## Restore Elasticsearch

```bash
docker compose stop worker               # stop new writes
docker compose exec elasticsearch curl -s 'localhost:9200/_snapshot/adsiem-backups/_all?pretty' | grep '"snapshot"'
SNAP=adsiem-2026.11.12-xxxxxxxx                          # pick one
# an open index can't be restored over: close (or delete) it first
docker compose exec elasticsearch curl -s -XPOST 'localhost:9200/logs,alert_iocs/_close'
docker compose exec elasticsearch curl -s -XPOST "localhost:9200/_snapshot/adsiem-backups/$SNAP/_restore" \
  -H 'Content-Type: application/json' -d '{"indices": "logs,alert_iocs"}'
docker compose start worker
```

If the restore answers `"failed": 1` for a shard, check
`curl -s -XPOST localhost:9200/_cluster/allocation/explain -H 'Content-Type: application/json' -d '{"index":"logs","shard":0,"primary":true}'`.
The usual cause is a disk past Elasticsearch's low watermark (85% used), where
it won't place a restored shard. Free space first, then close or delete the
index and restore again.

Lines that arrived after the snapshot was taken aren't in it. Alerts in Postgres
still point at those events, and the SOAR "alert event" step reports them as no
longer in the index.

## On a new host

1. Copy the repository and `BACKUP_DIR`.
2. `docker compose up -d postgres elasticsearch` and wait for both to be healthy.
3. Restore Postgres as above. With a fresh volume, `soc_platform` was just
   created by `db/init.sql`, so restore into it after dropping it, or use the
   rename swap.
4. Start the worker once so it registers the snapshot repository, then restore
   Elasticsearch as above.
5. `docker compose up -d`.
