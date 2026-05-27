# worker/worker/ai_consumer.py
import asyncio
import json
import structlog
from worker.config import AI_ANALYSIS_QUEUE
from worker.redis_client import get_redis
from worker.ai_analyst import analyze_and_maybe_create_case
from worker.ai_queue import mark_queued

log = structlog.get_logger()

async def ai_backfill_loop() -> None:
    """On startup: queue alerts that have no linked case and haven't been queued yet.
    Runs once, then checks every 5 minutes for newly missed alerts."""
    from sqlalchemy import select, text
    from worker.database import AsyncSessionLocal

    redis = await get_redis()

    while True:
        try:
            async with AsyncSessionLocal() as db:
                # Alerts with no linked case
                result = await db.execute(text("""
                    SELECT a.id, a.title, a.severity, a.source_ip, a.hostname, a.group_id
                    FROM alerts a
                    WHERE NOT EXISTS (
                        SELECT 1 FROM cases c WHERE c.alert_id = a.id
                    )
                    ORDER BY a.created_at DESC
                    LIMIT 200
                """))
                rows = result.fetchall()

            queued = 0
            for row in rows:
                alert_id = str(row.id)
                if await mark_queued(redis, alert_id):
                    await redis.rpush(AI_ANALYSIS_QUEUE, json.dumps({
                        "alert_id": alert_id,
                        "title": row.title,
                        "severity": row.severity,
                        "source_ip": row.source_ip,
                        "hostname": row.hostname,
                        "decoded_fields": {},
                        "group_id": row.group_id or "default",
                    }))
                    queued += 1

            if queued:
                log.info("ai_backfill_queued", count=queued, total_unprocessed=len(rows))

        except Exception as e:
            log.error("ai_backfill_error", error=str(e))

        await asyncio.sleep(300)  # recheck every 5 minutes

async def ai_analysis_loop() -> None:
    redis = await get_redis()
    log.info("ai_consumer_started", queue=AI_ANALYSIS_QUEUE)
    while True:
        try:
            item = await redis.blpop(AI_ANALYSIS_QUEUE, timeout=5)
            if not item:
                continue
            _, raw = item
            data = json.loads(raw)
            alert_id = data.get("alert_id", "")

            # mark as queued so backfill won't re-queue it
            await mark_queued(redis, alert_id)

            await analyze_and_maybe_create_case(
                alert_id=alert_id,
                title=data.get("title", ""),
                severity=data.get("severity", "medium"),
                source_ip=data.get("source_ip"),
                hostname=data.get("hostname"),
                decoded_fields=data.get("decoded_fields", {}),
                group_id=data.get("group_id", "default"),
            )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("ai_consumer_error", error=str(e))
            await asyncio.sleep(2)
