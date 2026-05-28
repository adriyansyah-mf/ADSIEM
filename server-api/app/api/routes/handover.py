# server-api/app/api/routes/handover.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, Case, ShiftHandover, User

router = APIRouter(prefix="/api/handover", tags=["handover"])


class HandoverCreate(BaseModel):
    shift_label: str = "day"
    summary: str
    notes: str = ""


class HandoverOut(BaseModel):
    id: UUID
    group_id: str
    shift_label: str
    summary: str
    open_alerts: int
    open_cases: int
    escalations: int
    created_at: str | None = None

    model_config = {"from_attributes": True}

    def model_post_init(self, __context):
        if self.created_at and hasattr(self.created_at, "isoformat"):
            object.__setattr__(self, "created_at", self.created_at.isoformat())


@router.get("", response_model=list[HandoverOut])
async def list_handovers(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    limit: int = Query(default=10, le=50),
):
    q = select(ShiftHandover).order_by(ShiftHandover.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(ShiftHandover.group_id == group_filter)
    return (await db.execute(q)).scalars().all()


@router.post("", response_model=HandoverOut, status_code=201)
async def create_handover(
    body: HandoverCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    gid = group_filter or user.group_id

    open_alerts = (await db.execute(
        select(func.count()).select_from(Alert)
        .where(Alert.group_id == gid, Alert.status.in_(["new", "in_progress"]))
    )).scalar() or 0

    open_cases = (await db.execute(
        select(func.count()).select_from(Case)
        .where(Case.group_id == gid, Case.status.in_(["open", "in_review"]))
    )).scalar() or 0

    escalations = (await db.execute(
        select(func.count()).select_from(Case)
        .where(Case.group_id == gid, Case.status == "escalated")
    )).scalar() or 0

    full_summary = body.summary
    if body.notes:
        full_summary += f"\n\nNotes:\n{body.notes}"

    h = ShiftHandover(
        group_id=gid,
        shift_label=body.shift_label,
        summary=full_summary,
        open_alerts=open_alerts,
        open_cases=open_cases,
        escalations=escalations,
        created_by=user.id,
    )
    db.add(h)
    await db.commit()
    await db.refresh(h)
    return h
