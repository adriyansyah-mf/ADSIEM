import redis.asyncio as aioredis

_QUEUED_KEY = "siem:ai-analysis:queued"
_TTL = 3600  # 1 hour — auto-expire so re-analysis is possible after an hour


async def mark_queued(redis: aioredis.Redis, alert_id: str) -> None:
    """Record that alert_id has been pushed to the AI analysis queue."""
    await redis.sadd(_QUEUED_KEY, alert_id)
    await redis.expire(_QUEUED_KEY, _TTL)


async def is_queued(redis: aioredis.Redis, alert_id: str) -> bool:
    """Return True if alert_id is already in the AI analysis queue set."""
    return bool(await redis.sismember(_QUEUED_KEY, alert_id))
