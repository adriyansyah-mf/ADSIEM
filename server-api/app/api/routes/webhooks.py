# server-api/app/api/routes/webhooks.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission, get_current_user
from app.models.models import User, WebhookConfig
from app.schemas.schemas import PaginatedResponse, WebhookCreate, WebhookOut, WebhookUpdate
from app.services.audit import audit_log

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

@router.get("", response_model=PaginatedResponse)
async def list_webhooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("agents:manage")),
    page: int = 1, page_size: int = 25,
):
    q = select(WebhookConfig)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[WebhookOut.model_validate(w) for w in result.scalars().all()])

@router.post("", response_model=WebhookOut, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    webhook = WebhookConfig(**body.model_dump())
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    background.add_task(audit_log, db, current_user.id, "webhook_created", "webhook", str(webhook.id))
    return WebhookOut.model_validate(webhook)

@router.put("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: UUID, body: WebhookUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    result = await db.execute(select(WebhookConfig).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(webhook, field, value)
    await db.commit()
    await db.refresh(webhook)
    background.add_task(audit_log, db, current_user.id, "webhook_updated", "webhook", str(webhook_id))
    return WebhookOut.model_validate(webhook)

@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    result = await db.execute(select(WebhookConfig).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(webhook)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "webhook_deleted", "webhook", str(webhook_id))
