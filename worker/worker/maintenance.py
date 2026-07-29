# worker/worker/maintenance.py
"""Data retention: purge old logs (Elasticsearch) and closed alerts (Postgres) on a daily schedule."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import delete

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
            if alrt_days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=alrt_days)
                async with AsyncSessionLocal() as db:
                    result = await db.execute(
                        delete(Alert)
                        .where(Alert.status.in_(["closed", "resolved"]))
                        .where(Alert.created_at < cutoff)
                    )
                    await db.commit()
                    n_alrt = result.rowcount or 0
            else:
                n_alrt = 0

            log.info("maintenance_done",
                     logs_deleted=n_evt,
                     alerts_deleted=n_alrt)
        except Exception as exc:
            log.error("maintenance_error", error=str(exc))

        await asyncio.sleep(RUN_INTERVAL)
