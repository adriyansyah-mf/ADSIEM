# worker/worker/ai_retry.py
"""Delayed retries for AI triage the LLM couldn't do (rate limit, quota,
timeout, router down).

An alert whose triage failed goes into a Redis sorted set scored by when to
try again; ai_retry_loop moves the due ones back onto the AI queue. Backoff
grows per attempt (with jitter, so a burst of rate-limited alerts doesn't
come back as a burst); after the last attempt the triage falls back for
good (worker.graph.triage_graph._fallback_verdict).
"""
import asyncio
import json
import random
import time

import structlog

from worker.config import AI_ANALYSIS_QUEUE

log = structlog.get_logger()

RETRY_KEY = "siem:ai-retry"            # zset: payload json -> due (unix seconds)
PENDING_KEY = "siem:ai-retry:pending"  # set of alert ids waiting for a retry
BACKOFF_SECONDS = (120, 300, 900, 1800, 3600)  # 2m, 5m, 15m, 30m, 1h: ~1h50 in all
MAX_ATTEMPTS = len(BACKOFF_SECONDS)
POLL_SECONDS = 10
BATCH = 20  # moved back per poll: the consumer spaces them out (DISPATCH_GAP_SECONDS)


def backoff(attempt: int) -> float | None:
    """Delay before retry number attempt+1, or None when attempts are used up."""
    if attempt >= MAX_ATTEMPTS:
        return None
    base = BACKOFF_SECONDS[attempt]
    return base + random.uniform(0, base * 0.2)


async def schedule(redis, payload: dict, attempt: int, now: float | None = None) -> float | None:
    """Queue payload (the AI queue's item) for another try. Returns the delay,
    or None when the alert has used its attempts."""
    delay = backoff(attempt)
    if delay is None:
        return None
    item = dict(payload, attempt=attempt + 1)
    await redis.zadd(RETRY_KEY, {json.dumps(item, sort_keys=True, default=str): (now or time.time()) + delay})
    await redis.sadd(PENDING_KEY, str(payload.get("alert_id", "")))
    await redis.expire(PENDING_KEY, 2 * 86400)
    return delay


async def is_pending(redis, alert_id: str) -> bool:
    return bool(await redis.sismember(PENDING_KEY, alert_id))


async def requeue_due(redis, now: float | None = None) -> int:
    """Move retries that are due back onto the AI queue. ZREM decides who
    moves an item, so two worker replicas never both requeue it."""
    due = await redis.zrangebyscore(RETRY_KEY, 0, now or time.time(), start=0, num=BATCH)
    moved = 0
    for raw in due:
        if not await redis.zrem(RETRY_KEY, raw):
            continue  # another replica took it
        try:
            alert_id = str(json.loads(raw).get("alert_id", ""))
        except (ValueError, AttributeError):
            continue
        await redis.srem(PENDING_KEY, alert_id)
        await redis.rpush(AI_ANALYSIS_QUEUE, raw)
        moved += 1
    if moved:
        log.info("ai_retry_requeued", count=moved)
    return moved


async def ai_retry_loop() -> None:
    from worker.redis_client import get_redis
    redis = await get_redis()
    while True:
        try:
            await requeue_due(redis)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("ai_retry_loop_error", error=str(exc))
        await asyncio.sleep(POLL_SECONDS)
