# server-api/app/api/routes/suppressions.py
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import AlertSuppression, User

router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])


class SuppressionCreate(BaseModel):
    entity_type: str   # ip | hostname | user | rule_title
    entity_value: str
    reason: str | None = None
    # a suppression that ends by itself: days from now, or an exact time; neither = never
    expires_in_days: int | None = Field(None, ge=1, le=365)
    expires_at: datetime | None = None


class SuppressionOut(BaseModel):
    id: UUID
    entity_type: str
    entity_value: str
    reason: str | None
    group_id: str
    is_active: bool
    # a datetime, sent as ISO 8601: declared as str it failed response validation (500)
    # after the row was already committed, so every retry stored another copy
    created_at: datetime | None = None
    expires_at: datetime | None = None
    hit_count: int = 0          # alerts it has hidden
    last_hit_at: datetime | None = None

    model_config = {"from_attributes": True}


@router.get("", response_model=list[SuppressionOut])
async def list_suppressions(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    q = select(AlertSuppression).where(AlertSuppression.is_active == True)
    if group_filter:
        q = q.where(AlertSuppression.group_id == group_filter)
    result = await db.execute(q.order_by(AlertSuppression.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=SuppressionOut, status_code=201)
async def create_suppression(
    body: SuppressionCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("alerts:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    allowed_types = {"ip", "hostname", "user", "rule_title"}
    if body.entity_type not in allowed_types:
        raise HTTPException(400, f"entity_type must be one of: {', '.join(allowed_types)}")
    value, group = body.entity_value.strip(), group_filter or user.group_id
    if not value:
        raise HTTPException(422, "entity_value is empty")
    expires_at = body.expires_at
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(422, "expires_at is in the past")
    # the same suppression clicked twice stays one row
    existing = (await db.execute(select(AlertSuppression).where(
        AlertSuppression.is_active == True, AlertSuppression.entity_type == body.entity_type,
        AlertSuppression.entity_value == value, AlertSuppression.group_id == group,
    ).limit(1))).scalars().first()
    if existing is not None:
        if existing.expires_at is not None and (expires_at is None or expires_at > existing.expires_at):
            # asked again: without an end it stays for good, a later end extends it (no second row)
            existing.expires_at = expires_at
            await db.commit()
            await db.refresh(existing)
        return existing
    s = AlertSuppression(
        entity_type=body.entity_type,
        entity_value=value,
        reason=body.reason,
        group_id=group,
        created_by=user.id,
        expires_at=expires_at,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


@router.delete("/{suppression_id}", status_code=204)
async def delete_suppression(
    suppression_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_permission("alerts:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    q = select(AlertSuppression).where(AlertSuppression.id == suppression_id)
    if group_filter is not None:
        q = q.where(AlertSuppression.group_id == group_filter)
    s = (await db.execute(q)).scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    s.is_active = False
    await db.commit()
