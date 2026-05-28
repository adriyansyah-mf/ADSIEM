# worker/worker/hunt_scheduler.py
"""Run scheduled threat hunts at their configured intervals."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import HuntSchedule, ThreatHunt

log = structlog.get_logger()

CHECK_INTERVAL = 1800  # check every 30 minutes


async def hunt_scheduler_loop() -> None:
    await asyncio.sleep(120)  # let other services settle on startup
    while True:
        try:
            now = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as db:
                schedules = (await db.execute(
                    select(HuntSchedule).where(HuntSchedule.is_enabled == True)
                )).scalars().all()

                for sched in schedules:
                    due_after = (sched.last_run_at or datetime.min.replace(tzinfo=timezone.utc)) + \
                                timedelta(hours=sched.interval_hours)
                    if now < due_after:
                        continue

                    hunt = ThreatHunt(
                        ioc_type=sched.ioc_type,
                        ioc_value=sched.ioc_value,
                        group_id=sched.group_id,
                        created_by=sched.created_by,
                    )
                    db.add(hunt)
                    sched.last_run_at = now
                    await db.flush()
                    log.info("scheduled_hunt_created",
                             schedule_name=sched.name,
                             ioc_type=sched.ioc_type,
                             ioc_value=sched.ioc_value,
                             hunt_id=str(hunt.id))

                await db.commit()
        except Exception as exc:
            log.error("hunt_scheduler_error", error=str(exc))

        await asyncio.sleep(CHECK_INTERVAL)
