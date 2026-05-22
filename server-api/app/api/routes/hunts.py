from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, ThreatHunt, User
from app.schemas.schemas import ThreatHuntCreate, ThreatHuntOut

router = APIRouter(tags=["hunts"])

_VALID_IOC_TYPES = {"ip", "hostname", "user", "hash"}


@router.post("/api/hunts", response_model=ThreatHuntOut, status_code=201)
async def create_hunt(
    body: ThreatHuntCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    ioc_type = body.ioc_type.lower()
    ioc_value = body.ioc_value.strip()

    # Auto-extract IoC from alert if alert_id given
    if body.alert_id and not ioc_value:
        result = await db.execute(select(Alert).where(Alert.id == body.alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        if ioc_type == "ip" and alert.source_ip:
            ioc_value = alert.source_ip
        elif ioc_type == "hostname" and alert.hostname:
            ioc_value = alert.hostname
        else:
            raise HTTPException(status_code=422, detail=f"Alert has no {ioc_type} to hunt")

    if ioc_type not in _VALID_IOC_TYPES:
        raise HTTPException(status_code=422, detail=f"ioc_type must be one of {_VALID_IOC_TYPES}")
    if not ioc_value:
        raise HTTPException(status_code=422, detail="ioc_value is required")

    hunt = ThreatHunt(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        group_id=current_user.group_id,
        created_by=current_user.id,
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


@router.get("/api/hunts", response_model=list[ThreatHuntOut])
async def list_hunts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=50, le=200),
):
    result = await db.execute(
        select(ThreatHunt).order_by(desc(ThreatHunt.created_at)).limit(limit)
    )
    return result.scalars().all()


@router.get("/api/hunts/{hunt_id}", response_model=ThreatHuntOut)
async def get_hunt(
    hunt_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    hunt = await db.get(ThreatHunt, hunt_id)
    if not hunt:
        raise HTTPException(status_code=404)
    return hunt
