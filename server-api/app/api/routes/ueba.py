# server-api/app/api/routes/ueba.py
from datetime import datetime, timezone, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import UebaEntityScore, UebaAnomaly, UebaFeatureSnapshot, User
from app.schemas.schemas import (
    UebaEntityScoreOut, UebaEntityDetailOut, UebaStatusOut,
    UebaAnomalyOut, UebaRiskHistoryPoint,
)
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
    entity_type: str = Query("all", pattern="^(user|ip|host|all)$"),
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
):
    q = select(UebaEntityScore).where(UebaEntityScore.risk_score >= min_risk)
    if entity_type != "all":
        q = q.where(UebaEntityScore.entity_type == entity_type)
    q = q.order_by(desc(UebaEntityScore.risk_score)).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [UebaEntityScoreOut.model_validate(r) for r in rows]


@router.get("/api/ueba/entity/{entity_type}/{entity_value}", response_model=UebaEntityDetailOut)
async def get_entity_detail(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
):
    score_row = await db.get(UebaEntityScore, (entity_type, entity_value))
    if score_row is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    anomaly_rows = (await db.execute(
        select(UebaAnomaly)
        .where(UebaAnomaly.entity_type == entity_type)
        .where(UebaAnomaly.entity_value == entity_value)
        .order_by(desc(UebaAnomaly.detected_at))
        .limit(50)
    )).scalars().all()

    return UebaEntityDetailOut(
        score=UebaEntityScoreOut.model_validate(score_row),
        anomalies=[UebaAnomalyOut.model_validate(a) for a in anomaly_rows],
    )


@router.get("/api/ueba/entity/{entity_type}/{entity_value}/history", response_model=list[UebaRiskHistoryPoint])
async def get_entity_risk_history(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    days: int = Query(7, ge=1, le=30),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(
        select(UebaFeatureSnapshot.snapshot_hour, UebaFeatureSnapshot.risk_score)
        .where(UebaFeatureSnapshot.entity_type == entity_type)
        .where(UebaFeatureSnapshot.entity_value == entity_value)
        .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        .order_by(UebaFeatureSnapshot.snapshot_hour.asc())
    )).all()
    return [UebaRiskHistoryPoint(snapshot_hour=r[0], risk_score=r[1]) for r in rows]


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

    host_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "host")
    )).scalar_one()

    return UebaStatusOut(
        status=status,
        trained_at=trained_at,
        user_snapshot_count=user_count,
        ip_snapshot_count=ip_count,
        host_snapshot_count=host_count,
    )
