# server-api/app/api/routes/ueba.py
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc, func, cast, Date
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import UebaEntityScore, UebaAnomaly, UebaFeatureSnapshot, User
from app.schemas.schemas import UebaEntityScoreOut, UebaEntityDetailOut, UebaStatusOut
from app.core.config import settings

router = APIRouter(tags=["ueba"])

_redis: aioredis.Redis | None = None

async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


@router.get("/api/ueba/entities", response_model=list[UebaEntityScoreOut])
async def get_entities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    entity_type: str = Query("all"),
    min_risk: float = Query(0.0),
    limit: int = Query(50, le=200),
):
    q = select(UebaEntityScore).where(UebaEntityScore.risk_score >= min_risk)
    if entity_type != "all":
        q = q.where(UebaEntityScore.entity_type == entity_type)
    q = q.order_by(desc(UebaEntityScore.risk_score)).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return rows


@router.get("/api/ueba/entity/{entity_type}/{entity_value}", response_model=UebaEntityDetailOut)
async def get_entity_detail(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
):
    score_row = await db.get(UebaEntityScore, (entity_type, entity_value))
    anomaly_rows = (await db.execute(
        select(UebaAnomaly)
        .where(UebaAnomaly.entity_type == entity_type)
        .where(UebaAnomaly.entity_value == entity_value)
        .order_by(desc(UebaAnomaly.detected_at))
        .limit(50)
    )).scalars().all()

    if score_row is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Entity not found")

    return UebaEntityDetailOut(score=score_row, anomalies=anomaly_rows)


@router.get("/api/ueba/status", response_model=UebaStatusOut)
async def get_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
):
    redis = await _get_redis()
    status     = await redis.get("ueba:model:status") or "cold"
    trained_at = await redis.get("ueba:model:trained_at")

    user_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "user")
    )).scalar_one()

    ip_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "ip")
    )).scalar_one()

    return UebaStatusOut(
        status=status,
        trained_at=trained_at,
        user_snapshot_count=user_count,
        ip_snapshot_count=ip_count,
    )


@router.get("/api/ueba/{entity_type}/{entity_value}/history")
async def entity_risk_history(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    days: int = Query(default=30, le=90),
):
    """Return daily risk score history for a UEBA entity."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    daily_q = (
        select(
            cast(UebaAnomaly.detected_at, Date).label("day"),
            func.max(UebaAnomaly.risk_score).label("max_risk"),
            func.count().label("anomaly_count"),
        )
        .where(
            UebaAnomaly.entity_type == entity_type,
            UebaAnomaly.entity_value == entity_value,
            UebaAnomaly.detected_at >= since,
        )
        .group_by(cast(UebaAnomaly.detected_at, Date))
        .order_by(cast(UebaAnomaly.detected_at, Date).asc())
    )
    rows = (await db.execute(daily_q)).all()

    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "days": days,
        "history": [
            {"day": str(r.day), "max_risk": round(r.max_risk, 1), "anomaly_count": r.anomaly_count}
            for r in rows
        ],
    }
