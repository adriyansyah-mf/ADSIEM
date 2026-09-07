# P0 Backup/Restore Drill

## Backup evidence

- PostgreSQL custom-format dump created: `backups/postgres/soc_platform-20260905T235657Z.dump`.
- `pg_restore --list` succeeded and reported 274 TOC entries.
- Elasticsearch filesystem snapshot created: `snapshot-20260906t000004-3226654`.
- Elasticsearch snapshot state is `SUCCESS` for the `logs` index.
- SHA-256 manifests were generated for both metadata artifacts.

## Restore status

Restore drill completed in disposable targets: PostgreSQL database `soc_restore_drill` restored successfully with `restored_alert_count=110`, then was dropped. Elasticsearch snapshot was restored as `logs_restore_debug` with `count=7294`, then deleted. The ES disk watermark temporarily blocked allocation; the drill disabled the transient disk threshold for the restore and restored the setting immediately afterward. The active database and `logs` index were not overwritten.
