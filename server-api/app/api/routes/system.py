# server-api/app/api/routes/system.py
import time
from typing import Annotated
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.services.evidence_inbox import check_evidence_durability
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from app.core.database import engine, get_db
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


@router.get("/ready")
async def ready(db: Annotated[AsyncSession, Depends(get_db)]) -> JSONResponse:
    if not settings.EVIDENCE_INGEST_ENABLED:
        return JSONResponse({"status": "ok", "evidence": "disabled"})
    healthy = await check_evidence_durability(db)
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "evidence": "ready" if healthy else "unavailable"},
        status_code=200 if healthy else 503,
    )
