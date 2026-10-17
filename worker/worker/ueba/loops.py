# worker/worker/ueba/loops.py
import asyncio
import structlog
from worker.redis_client import get_redis
from worker.ueba.trainer import take_snapshots, train_models

log = structlog.get_logger()


async def ueba_snapshot_loop() -> None:
    """Save hourly feature snapshots to DB for training data."""
    redis = await get_redis()
    # Stagger start so first snapshot happens 5 min after worker boot
    await asyncio.sleep(300)
    while True:
        try:
            await take_snapshots(redis)
        except Exception as exc:
            log.error("ueba_snapshot_failed", error=str(exc))
        await asyncio.sleep(3600)


async def ueba_train_loop() -> None:
    """Retrain Isolation Forest models every hour."""
    redis = await get_redis()
    # Stagger 10 min after snapshot loop so first training has data
    await asyncio.sleep(600)
    while True:
        try:
            await train_models(redis)
        except Exception as exc:
            log.error("ueba_train_failed", error=str(exc))
        await asyncio.sleep(3600)


# AI review of UEBA happens on the alert path: the scorer raises an alert that
# carries the anomaly's reasons, ai_analyst adds the entity's history to the
# triage prompt, and the verdict is written back onto the anomaly
# (ai_analyst._ueba_context / _record_ueba_outcome).
