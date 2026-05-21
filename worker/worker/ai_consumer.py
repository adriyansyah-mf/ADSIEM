# worker/worker/ai_consumer.py
import asyncio
import json
import structlog
from worker.config import AI_ANALYSIS_QUEUE
from worker.redis_client import get_redis
from worker.ai_analyst import analyze_and_maybe_create_case

log = structlog.get_logger()

async def ai_analysis_loop() -> None:
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
            await analyze_and_maybe_create_case(
                alert_id=data.get("alert_id", ""),
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
