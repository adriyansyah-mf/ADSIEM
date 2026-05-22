# worker/worker/redis_client.py
import redis.asyncio as aioredis
from worker.config import REDIS_URL

_redis: aioredis.Redis | None = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis
