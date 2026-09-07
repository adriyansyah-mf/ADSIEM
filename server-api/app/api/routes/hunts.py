from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, ThreatHunt, User
from app.schemas.schemas import ThreatHuntCreate, ThreatHuntOut

router = APIRouter(tags=["hunts"])

_VALID_IOC_TYPES = {"ip", "hostname", "user", "hash"}


@router.post("/api/hunts", response_model=ThreatHuntOut, status_code=201)
async def create_hunt(
    body: ThreatHuntCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    ioc_type = body.ioc_type.lower()
    ioc_value = body.ioc_value.strip()

    # Auto-extract IoC from alert if alert_id given
    if body.alert_id and not ioc_value:
        alert_query = select(Alert).where(Alert.id == body.alert_id)
        if group_filter is not None:
            alert_query = alert_query.where(Alert.group_id == group_filter)
        result = await db.execute(alert_query)
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
        group_id=group_filter or current_user.group_id,
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    limit: int = Query(default=50, le=200),
):
    q = select(ThreatHunt).order_by(desc(ThreatHunt.created_at)).limit(limit)
    if group_filter:
        q = q.where(ThreatHunt.group_id == group_filter)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/api/hunts/{hunt_id}", response_model=ThreatHuntOut)
async def get_hunt(
    hunt_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(ThreatHunt).where(ThreatHunt.id == hunt_id)
    if group_filter is not None:
        query = query.where(ThreatHunt.group_id == group_filter)
    hunt = (await db.execute(query)).scalar_one_or_none()
    if not hunt:
        raise HTTPException(status_code=404)
    return hunt
