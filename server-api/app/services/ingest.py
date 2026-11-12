import json
import time
from datetime import datetime
import redis.asyncio as aioredis
from fastapi import HTTPException, Request
from app.core.config import settings

BACKPRESSURE_HEADER = "X-Ingest-Backpressure"
_BACKLOG_TTL = 1.0  # seconds: one XLEN per second per process, not per request
_backlog = {"at": 0.0, "length": 0}


async def stream_backlog(redis: aioredis.Redis) -> int:
    """Entries in the log stream (stream_maintenance trims only processed ones,
    so this is what the workers still have to get through), cached briefly."""
    now = time.monotonic()
    if now - _backlog["at"] > _BACKLOG_TTL:
        try:
            _backlog["length"] = int(await redis.xlen(settings.REDIS_STREAM_KEY))
        except Exception:  # noqa: BLE001 — can't tell: don't refuse logs over it
            _backlog["length"] = 0
        _backlog["at"] = now
    return _backlog["length"]


async def refuse_if_backlogged(request: Request | None, redis: aioredis.Redis) -> None:
    """429 + Retry-After when the workers are far behind, but only to agents that
    said they retry it (agents before this header treat any 4xx as "sent" and
    would drop the lines)."""
    if request is None or request.headers.get(BACKPRESSURE_HEADER) != "1":
        return
    if await stream_backlog(redis) >= settings.INGEST_BACKLOG_LIMIT:
        raise HTTPException(status_code=429, detail="ingest_backlog",
                            headers={"Retry-After": str(settings.INGEST_RETRY_AFTER_SECONDS)})


async def enqueue_log(redis: aioredis.Redis, payload: dict) -> str:
    data = {k: str(v) if isinstance(v, datetime) else json.dumps(v) if isinstance(v, dict) else str(v)
            for k, v in payload.items()}
    return await redis.xadd(settings.REDIS_STREAM_KEY, data,
                            maxlen=settings.REDIS_STREAM_MAXLEN, approximate=True)
