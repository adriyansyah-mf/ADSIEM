# server-api/app/api/routes/queues.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import User, WebhookDelivery
from app.services.audit import audit_log

router = APIRouter(prefix="/api/queues", tags=["queues"])
Perm = require_permission("queues:manage")

_FAILED_STREAM = f"{settings.REDIS_STREAM_KEY}:failed"
_DEAD_STREAM = f"{settings.REDIS_STREAM_KEY}:dead"


def _delivery_out(d: WebhookDelivery) -> dict:
    return {
        "id": str(d.id),
        "alert_id": str(d.alert_id),
        "webhook_config_id": str(d.webhook_config_id),
        "group_id": d.group_id,
        "status": d.status,
        "attempts": d.attempts,
        "last_error": d.last_error,
        "error_class": d.error_class,
        "first_failed_at": d.first_failed_at.isoformat() if d.first_failed_at else None,
        "last_attempted_at": d.last_attempted_at.isoformat() if d.last_attempted_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


async def _stream_metrics(redis, key: str) -> dict:
    length = await redis.xlen(key)
    oldest_age_seconds = None
    if length:
        entries = await redis.xrange(key, count=1)
        if entries:
            entry_id = entries[0][0]
            # Redis stream IDs are "<millis>-<seq>"; the millis prefix is the
            # entry's creation time, giving oldest-age without storing it separately.
            entry_ms = int(entry_id.split("-")[0])
            oldest_age_seconds = max(0, int(datetime.now(timezone.utc).timestamp() - entry_ms / 1000))
    return {"depth": length, "oldest_age_seconds": oldest_age_seconds}


@router.get("/metrics")
async def queue_metrics(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(WebhookDelivery).where(WebhookDelivery.status.in_(["pending", "failed"]))
    if group_filter is not None:
        query = query.where(WebhookDelivery.group_id == group_filter)
    rows = (await db.execute(query)).scalars().all()
    pending = [d for d in rows if d.status == "pending"]
    failed = [d for d in rows if d.status == "failed"]
    oldest_pending_age = None
    if pending:
        oldest = min(pending, key=lambda d: d.created_at)
        oldest_pending_age = int((datetime.now(timezone.utc) - oldest.created_at).total_seconds())

    redis = await get_redis()
    ingestion_failed = await _stream_metrics(redis, _FAILED_STREAM)
    ingestion_dead = await _stream_metrics(redis, _DEAD_STREAM)

    return {
        "webhook_deliveries": {
            "pending": len(pending),
            "failed": len(failed),
            "oldest_pending_age_seconds": oldest_pending_age,
        },
        "ingestion_dlq": ingestion_failed,
        "ingestion_dead_letter": ingestion_dead,
    }


@router.get("/webhook-deliveries")
async def list_webhook_deliveries(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    status: str | None = None,
    limit: int = 100,
):
    query = select(WebhookDelivery).order_by(WebhookDelivery.created_at.desc()).limit(min(limit, 500))
    if group_filter is not None:
        query = query.where(WebhookDelivery.group_id == group_filter)
    if status:
        query = query.where(WebhookDelivery.status == status)
    rows = (await db.execute(query)).scalars().all()
    return [_delivery_out(d) for d in rows]


async def _load_delivery(db: AsyncSession, delivery_id: UUID, group_filter: str | None) -> WebhookDelivery:
    query = select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
    if group_filter is not None:
        query = query.where(WebhookDelivery.group_id == group_filter)
    delivery = (await db.execute(query)).scalar_one_or_none()
    if delivery is None:
        raise HTTPException(status_code=404, detail="Webhook delivery not found")
    return delivery


@router.post("/webhook-deliveries/{delivery_id}/retry")
async def retry_webhook_delivery(
    delivery_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    delivery = await _load_delivery(db, delivery_id, group_filter)
    delivery.status = "pending"
    delivery.attempts = 0
    delivery.last_attempted_at = None
    await db.commit()
    await db.refresh(delivery)
    background.add_task(
        audit_log, db, current_user, "webhook_delivery_retried", "webhook_delivery", str(delivery_id)
    )
    return _delivery_out(delivery)


@router.post("/webhook-deliveries/{delivery_id}/discard")
async def discard_webhook_delivery(
    delivery_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    delivery = await _load_delivery(db, delivery_id, group_filter)
    delivery.status = "discarded"
    await db.commit()
    await db.refresh(delivery)
    background.add_task(
        audit_log, db, current_user, "webhook_delivery_discarded", "webhook_delivery", str(delivery_id)
    )
    return _delivery_out(delivery)
