# worker/worker/agent_monitor.py
"""Mark agents offline if they stop sending heartbeats."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import update, select

from worker.database import AsyncSessionLocal
from worker.models import Agent

log = structlog.get_logger()

OFFLINE_AFTER_SECONDS = 300  # 5 minutes without heartbeat → offline
CHECK_INTERVAL = 60


async def agent_monitor_loop() -> None:
    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=OFFLINE_AFTER_SECONDS)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    update(Agent)
                    .where(Agent.status == "online")
                    .where(Agent.last_seen_at < cutoff)
                    .returning(Agent.id, Agent.hostname)
                )
                went_offline = result.fetchall()
                if went_offline:
                    await db.commit()
                    for row in went_offline:
                        log.info("agent_went_offline", agent_id=str(row[0]), hostname=row[1])
        except Exception as exc:
            log.error("agent_monitor_error", error=str(exc))

        await asyncio.sleep(CHECK_INTERVAL)
