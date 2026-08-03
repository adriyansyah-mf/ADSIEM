# worker/worker/ai_consumer.py
import asyncio
import json
import structlog
from worker.config import AI_ANALYSIS_QUEUE
from worker.redis_client import get_redis
from worker.ai_analyst import analyze_and_maybe_create_case

log = structlog.get_logger()

# Gap between dispatching successive alerts to the AI queue. Without this,
# a burst of alerts (e.g. a scanner flood) gets ensure_future'd back to
# back with zero spacing — the 3-concurrent semaphore in llm_client.py caps
# how many run *at once*, but refills a freed slot instantly, so the LLM
# router gets hammered continuously and burns through provider rate/token
# limits (and paid-credit balances) in seconds.
DISPATCH_GAP_SECONDS = 3

async def _analyze_one(data: dict) -> None:
    try:
        await analyze_and_maybe_create_case(
            alert_id=data.get("alert_id", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "medium"),
            source_ip=data.get("source_ip"),
            hostname=data.get("hostname"),
            decoded_fields=data.get("decoded_fields", {}),
            group_id=data.get("group_id", "default"),
        )
    except Exception as e:
        log.error("ai_consumer_item_failed", alert_id=data.get("alert_id"), error=str(e))


async def ai_analysis_loop() -> None:
    """Pop alerts off the AI queue and analyse them concurrently.

    Each alert is dispatched as its own task rather than awaited in-line —
    LLM calls are already capped at 3 concurrent (see llm_client.py's
    semaphore), but a single item awaited here would otherwise let one
    rate-limited or slow alert block every alert queued behind it,
    regardless of severity.
    """
    redis = await get_redis()
    log.info("ai_consumer_started", queue=AI_ANALYSIS_QUEUE)
    while True:
        try:
            # BLPOP with 5s timeout
            item = await redis.blpop(AI_ANALYSIS_QUEUE, timeout=5)
            if not item:
                continue
            _, raw = item
            data = json.loads(raw)
            asyncio.ensure_future(_analyze_one(data))
            await asyncio.sleep(DISPATCH_GAP_SECONDS)
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("ai_consumer_error", error=str(e))
            await asyncio.sleep(2)


async def ai_backfill_loop() -> None:
    """Analyse unprocessed alerts (status='new') that were created before the AI consumer started."""
    from worker.database import AsyncSessionLocal
    from worker.models import Alert
    from sqlalchemy import select
    BACKFILL_INTERVAL = 3600  # run once per hour
    await asyncio.sleep(120)  # let the main consumer start first
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(
                    select(Alert).where(Alert.status == "new").order_by(Alert.created_at.desc()).limit(50)
                )).scalars().all()
            for alert in rows:
                try:
                    await analyze_and_maybe_create_case(
                        alert_id=str(alert.id),
                        title=alert.title,
                        severity=alert.severity,
                        source_ip=getattr(alert, "source_ip", None),
                        hostname=getattr(alert, "hostname", None),
                        decoded_fields={},
                        group_id=alert.group_id or "default",
                    )
                except Exception as exc:
                    log.error("ai_backfill_item_failed", alert_id=str(alert.id), error=str(exc))
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("ai_backfill_error", error=str(exc))
        await asyncio.sleep(BACKFILL_INTERVAL)
