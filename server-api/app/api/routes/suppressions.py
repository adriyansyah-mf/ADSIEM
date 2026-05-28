# server-api/app/api/routes/suppressions.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
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


class SuppressionOut(BaseModel):
    id: UUID
    entity_type: str
    entity_value: str
    reason: str | None
    group_id: str
    is_active: bool
    created_at: str | None = None

    model_config = {"from_attributes": True}

    def model_post_init(self, __context):
        if self.created_at and hasattr(self.created_at, "isoformat"):
            object.__setattr__(self, "created_at", self.created_at.isoformat())


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
    s = AlertSuppression(
        entity_type=body.entity_type,
        entity_value=body.entity_value.strip(),
        reason=body.reason,
        group_id=group_filter or user.group_id,
        created_by=user.id,
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
):
    s = (await db.execute(select(AlertSuppression).where(AlertSuppression.id == suppression_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    s.is_active = False
    await db.commit()
