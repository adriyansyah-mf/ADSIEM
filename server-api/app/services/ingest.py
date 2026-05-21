import json
from datetime import datetime
import redis.asyncio as aioredis
from app.core.config import settings

async def enqueue_log(redis: aioredis.Redis, payload: dict) -> str:
    data = {k: str(v) if isinstance(v, datetime) else json.dumps(v) if isinstance(v, dict) else str(v)
            for k, v in payload.items()}
    return await redis.xadd(settings.REDIS_STREAM_KEY, data)
