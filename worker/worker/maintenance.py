# worker/worker/maintenance.py
"""Data retention: purge old logs (Elasticsearch) and closed alerts (Postgres) on a daily schedule."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import delete

from worker import alert_iocs, es_client, es_snapshots
from worker.database import AsyncSessionLocal
from worker.models import Alert
from worker.settings_cache import get_setting
from worker.es_client import delete_by_query as es_delete_by_query

log = structlog.get_logger()

RUN_INTERVAL = 86400  # once per day


async def _purge_logs(days: int) -> int:
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return await es_delete_by_query({"range": {"created_at": {"lt": cutoff.isoformat()}}})


async def _purge_alerts(days: int) -> int:
    """Closed/resolved alerts older than `days`, with their alert_iocs documents."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            delete(Alert)
            .where(Alert.status.in_(["closed", "resolved"]))
            .where(Alert.created_at < cutoff)
            .returning(Alert.id)
        )
        deleted = [str(i) for i in result.scalars().all()]
        await db.commit()
    await alert_iocs.delete_for_alerts(deleted)
    return len(deleted)


async def maintenance_loop() -> None:
    await asyncio.sleep(300)  # wait 5 min after startup before first run
    while True:
        try:
            raw_days  = int(await get_setting("retention_raw_logs_days",  "30"))
            evt_days  = int(await get_setting("retention_events_days",    "90"))
            alrt_days = int(await get_setting("retention_alerts_days",   "180"))

            # raw_message + decoded_fields now live in the same ES document, so a
            # single purge applies — use the longer of the two settings so nothing
            # is deleted earlier than the old separate "events" retention did.
            log_days = max(raw_days, evt_days)
            n_evt = await _purge_logs(log_days)

            # only delete closed/resolved alerts older than threshold
            n_alrt = await _purge_alerts(alrt_days)

            # re-assert the snapshot repository/policy (a recreated cluster heals) and
            # report how fresh the last snapshot is
            snap: dict = {}
            try:
                if await es_snapshots.ensure(es_client._get_client()):
                    snap = await es_snapshots.last_status(es_client._get_client())
            except Exception as snap_exc:  # noqa: BLE001
                log.warning("es_snapshot_check_failed", error=str(snap_exc))

            log.info("maintenance_done",
                     logs_deleted=n_evt,
                     alerts_deleted=n_alrt,
                     snapshot_last_success=snap.get("last_success"),
                     snapshot_last_failure=snap.get("last_failure"))
        except Exception as exc:
            log.error("maintenance_error", error=str(exc))

        await asyncio.sleep(RUN_INTERVAL)
