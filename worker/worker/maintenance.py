# worker/worker/maintenance.py
"""Data retention: purge old raw_logs, events, and closed alerts on a daily schedule."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import delete, text

from worker.database import AsyncSessionLocal
from worker.models import RawLog, Event, Alert
from worker.settings_cache import get_setting

log = structlog.get_logger()

RUN_INTERVAL = 86400  # once per day


async def _purge(model, ts_col, days: int, label: str) -> int:
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            delete(model).where(ts_col < cutoff)
        )
        await db.commit()
        return result.rowcount or 0


async def maintenance_loop() -> None:
    await asyncio.sleep(300)  # wait 5 min after startup before first run
    while True:
        try:
            raw_days  = int(await get_setting("retention_raw_logs_days",  "30"))
            evt_days  = int(await get_setting("retention_events_days",    "90"))
            alrt_days = int(await get_setting("retention_alerts_days",   "180"))

            n_raw  = await _purge(RawLog, RawLog.received_at,     raw_days,  "raw_logs")
            n_evt  = await _purge(Event,  Event.created_at,       evt_days,  "events")

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
                     raw_logs_deleted=n_raw,
                     events_deleted=n_evt,
                     alerts_deleted=n_alrt)
        except Exception as exc:
            log.error("maintenance_error", error=str(exc))

        await asyncio.sleep(RUN_INTERVAL)
