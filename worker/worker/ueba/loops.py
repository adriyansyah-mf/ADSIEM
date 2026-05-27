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


async def ueba_ai_loop() -> None:
    """Background loop for UEBA AI investigator — reads siem:ueba:investigate queue."""
    from worker.ueba.investigator import ueba_investigator_loop
    redis = await get_redis()
    await ueba_investigator_loop(redis)
