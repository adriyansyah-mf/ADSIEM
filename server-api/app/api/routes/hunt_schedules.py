# server-api/app/api/routes/hunt_schedules.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import HuntSchedule, User

router = APIRouter(prefix="/api/hunt-schedules", tags=["hunts"])

_VALID_IOC_TYPES = {"ip", "hostname", "user", "hash"}


class HuntScheduleCreate(BaseModel):
    name: str
    ioc_type: str
    ioc_value: str
    interval_hours: int = 24


class HuntScheduleOut(BaseModel):
    id: UUID
    name: str
    ioc_type: str
    ioc_value: str
    interval_hours: int
    group_id: str
    is_enabled: bool
    last_run_at: str | None = None
    created_at: str | None = None

    model_config = {"from_attributes": True}

    def model_post_init(self, __context):
        for field in ("last_run_at", "created_at"):
            v = getattr(self, field)
            if v and hasattr(v, "isoformat"):
                object.__setattr__(self, field, v.isoformat())


@router.get("", response_model=list[HuntScheduleOut])
async def list_schedules(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    q = select(HuntSchedule).order_by(HuntSchedule.created_at.desc())
    if group_filter:
        q = q.where(HuntSchedule.group_id == group_filter)
    return (await db.execute(q)).scalars().all()


@router.post("", response_model=HuntScheduleOut, status_code=201)
async def create_schedule(
    body: HuntScheduleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    if body.ioc_type not in _VALID_IOC_TYPES:
        raise HTTPException(400, f"ioc_type must be one of {_VALID_IOC_TYPES}")
    s = HuntSchedule(
        name=body.name,
        ioc_type=body.ioc_type,
        ioc_value=body.ioc_value.strip(),
        interval_hours=max(1, body.interval_hours),
        group_id=group_filter or user.group_id,
        created_by=user.id,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


@router.patch("/{schedule_id}/toggle", response_model=HuntScheduleOut)
async def toggle_schedule(
    schedule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    s = (await db.execute(select(HuntSchedule).where(HuntSchedule.id == schedule_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    s.is_enabled = not s.is_enabled
    await db.commit()
    await db.refresh(s)
    return s


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    s = (await db.execute(select(HuntSchedule).where(HuntSchedule.id == schedule_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404)
    await db.delete(s)
    await db.commit()
