# server-api/app/api/routes/system.py
import time
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from app.core.database import engine
from app.core.redis_client import get_redis

router = APIRouter(tags=["system"])
_start_time = time.time()

@router.get("/health")
async def health():
    redis = await get_redis()
    checks = {"postgres": "ok", "redis": "ok"}
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception:
        checks["postgres"] = "error"
    try:
        await redis.ping()
    except Exception:
        checks["redis"] = "error"
    status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, **checks, "uptime_seconds": int(time.time() - _start_time)}

@router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
