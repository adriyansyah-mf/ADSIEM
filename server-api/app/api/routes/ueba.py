# server-api/app/api/routes/ueba.py
from datetime import datetime, timezone, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
import json

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import UebaEntityScore, UebaAnomaly, UebaFeatureSnapshot, User
from app.schemas.schemas import (
    UebaEntityScoreListOut, UebaEntityScoreOut, UebaEntityDetailOut, UebaStatusOut,
    UebaAnomalyOut, UebaRiskHistoryPoint,
)
from app.core.config import settings

router = APIRouter(tags=["ueba"])

_VALID_ENTITY_TYPES = {"user", "ip", "host"}
_TRAINING_WINDOW_DAYS = 7

_redis: aioredis.Redis | None = None

async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


def _validate_entity_type(entity_type: str) -> str:
    if entity_type not in _VALID_ENTITY_TYPES:
        raise HTTPException(status_code=422, detail=f"entity_type must be one of: {sorted(_VALID_ENTITY_TYPES)}")
    return entity_type


# ── Entity list ───────────────────────────────────────────────────────────────

@router.get("/api/ueba/entities", response_model=list[UebaEntityScoreListOut])
async def get_entities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
    entity_type: str = Query("all", pattern="^(user|ip|host|all)$"),
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    q = select(UebaEntityScore).where(UebaEntityScore.risk_score >= min_risk)
    if group_id:
        q = q.where(UebaEntityScore.group_id == group_id)
    if entity_type != "all":
        q = q.where(UebaEntityScore.entity_type == entity_type)
    q = q.order_by(desc(UebaEntityScore.risk_score)).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [UebaEntityScoreListOut.model_validate(r) for r in rows]


# ── Entity detail ─────────────────────────────────────────────────────────────

@router.get("/api/ueba/entity/{entity_type}/{entity_value}", response_model=UebaEntityDetailOut)
async def get_entity_detail(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
    anomaly_limit: int = Query(50, ge=1, le=200),
    anomaly_offset: int = Query(0, ge=0),
):
    _validate_entity_type(entity_type)

    score_row = await db.get(UebaEntityScore, (entity_type, entity_value))
    if score_row is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if group_id and score_row.group_id != group_id:
        raise HTTPException(status_code=404, detail="Entity not found")

    anomaly_q = (
        select(UebaAnomaly)
        .where(UebaAnomaly.entity_type == entity_type)
        .where(UebaAnomaly.entity_value == entity_value)
    )
    if group_id:
        anomaly_q = anomaly_q.where(UebaAnomaly.group_id == group_id)
    anomaly_q = anomaly_q.order_by(desc(UebaAnomaly.detected_at)).offset(anomaly_offset).limit(anomaly_limit)
    anomaly_rows = (await db.execute(anomaly_q)).scalars().all()

    return UebaEntityDetailOut(
        score=UebaEntityScoreOut.model_validate(score_row),
        anomalies=[UebaAnomalyOut.model_validate(a) for a in anomaly_rows],
    )


# ── Risk history ──────────────────────────────────────────────────────────────

@router.get("/api/ueba/entity/{entity_type}/{entity_value}/history", response_model=list[UebaRiskHistoryPoint])
async def get_entity_risk_history(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
    days: int = Query(7, ge=1, le=30),
):
    _validate_entity_type(entity_type)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    q = (
        select(UebaFeatureSnapshot.snapshot_hour, UebaFeatureSnapshot.risk_score)
        .where(UebaFeatureSnapshot.entity_type == entity_type)
        .where(UebaFeatureSnapshot.entity_value == entity_value)
        .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
    )
    if group_id:
        q = q.where(UebaFeatureSnapshot.group_id == group_id)
    q = q.order_by(UebaFeatureSnapshot.snapshot_hour.asc())

    rows = (await db.execute(q)).all()
    return [UebaRiskHistoryPoint(snapshot_hour=r[0], risk_score=r[1]) for r in rows]


# ── Global anomaly feed ───────────────────────────────────────────────────────

@router.get("/api/ueba/anomalies", response_model=list[UebaAnomalyOut])
async def get_anomalies(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
    entity_type: str = Query("all", pattern="^(user|ip|host|all)$"),
    ai_action: str = Query("all", pattern="^(escalate|alert|dismiss|all)$"),
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = (
        select(UebaAnomaly)
        .where(UebaAnomaly.detected_at >= cutoff)
        .where(UebaAnomaly.risk_score >= min_risk)
    )
    if group_id:
        q = q.where(UebaAnomaly.group_id == group_id)
    if entity_type != "all":
        q = q.where(UebaAnomaly.entity_type == entity_type)
    if ai_action != "all":
        q = q.where(UebaAnomaly.ai_action == ai_action)
    q = q.order_by(desc(UebaAnomaly.detected_at)).offset(offset).limit(limit)

    rows = (await db.execute(q)).scalars().all()
    return [UebaAnomalyOut.model_validate(r) for r in rows]


# ── Manual investigation trigger ──────────────────────────────────────────────

@router.post("/api/ueba/entity/{entity_type}/{entity_value}/investigate", status_code=202)
async def trigger_investigation(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
):
    """Push entity to investigation queue immediately, bypassing score/cooldown thresholds."""
    _validate_entity_type(entity_type)

    score_row = await db.get(UebaEntityScore, (entity_type, entity_value))
    if score_row is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if group_id and score_row.group_id != group_id:
        raise HTTPException(status_code=404, detail="Entity not found")

    redis = await _get_redis()

    # Bypass cooldown for manual trigger
    inv_cd_key = f"ueba:inv_cd:{entity_type}:{entity_value}"
    await redis.delete(inv_cd_key)

    payload = json.dumps({
        "entity_type":   entity_type,
        "entity_value":  entity_value,
        "group_id":      score_row.group_id,
        "anomaly_score": -0.5,
        "risk_score":    score_row.risk_score,
        "features":      {},
        "anomaly_id":    "",
        "source_ip":     entity_value if entity_type == "ip" else None,
        "hostname":      entity_value if entity_type == "host" else None,
        "manual":        True,
    })
    await redis.rpush("siem:ueba:investigate", payload)

    return {"queued": True, "entity_type": entity_type, "entity_value": entity_value}


# ── Status ────────────────────────────────────────────────────────────────────

@router.get("/api/ueba/status", response_model=UebaStatusOut)
async def get_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:read"))],
    group_id: Annotated[str | None, Depends(get_scoped_group)],
):
    redis = await _get_redis()
    status     = await redis.get("ueba:model:status") or "cold"
    trained_at = await redis.get("ueba:model:trained_at")

    # Count only snapshots within the active training window (7 days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=_TRAINING_WINDOW_DAYS)

    def _count_q(etype: str):
        q = (
            select(func.count())
            .select_from(UebaFeatureSnapshot)
            .where(UebaFeatureSnapshot.entity_type == etype)
            .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        )
        if group_id:
            q = q.where(UebaFeatureSnapshot.group_id == group_id)
        return q

    user_count = (await db.execute(_count_q("user"))).scalar_one()
    ip_count   = (await db.execute(_count_q("ip"))).scalar_one()
    host_count = (await db.execute(_count_q("host"))).scalar_one()

    return UebaStatusOut(
        status=status,
        trained_at=trained_at,
        user_snapshot_count=user_count,
        ip_snapshot_count=ip_count,
        host_snapshot_count=host_count,
    )
