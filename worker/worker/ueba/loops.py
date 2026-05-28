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
    """Run AI narrative generation for high-risk UEBA anomalies that have no narrative yet."""
    from worker.database import AsyncSessionLocal
    from worker.models import UebaAnomaly
    from worker.ai_analyst import analyze_and_maybe_create_case
    from sqlalchemy import select
    INTERVAL = 1800  # every 30 minutes
    await asyncio.sleep(900)  # stagger after train loop
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(
                    select(UebaAnomaly)
                    .where(UebaAnomaly.ai_narrative == None, UebaAnomaly.risk_score >= 70)
                    .order_by(UebaAnomaly.id.desc())
                    .limit(20)
                )).scalars().all()
            for anomaly in rows:
                try:
                    await analyze_and_maybe_create_case(
                        alert_id=str(anomaly.id),
                        title=f"UEBA: {anomaly.entity_type} anomaly — {anomaly.entity_value}",
                        severity="high" if anomaly.risk_score >= 85 else "medium",
                        source_ip=None,
                        hostname=anomaly.entity_value if anomaly.entity_type == "hostname" else None,
                        decoded_fields={"ueba_risk_score": anomaly.risk_score},
                        group_id=anomaly.group_id or "default",
                    )
                except Exception as exc:
                    log.error("ueba_ai_item_failed", anomaly_id=str(anomaly.id), error=str(exc))
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("ueba_ai_loop_error", error=str(exc))
        await asyncio.sleep(INTERVAL)
