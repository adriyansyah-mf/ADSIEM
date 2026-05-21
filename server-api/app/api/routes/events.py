# server-api/app/api/routes/events.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Event
from app.schemas.schemas import EventOut, PaginatedResponse

router = APIRouter(prefix="/api/events", tags=["events"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    page: int = 1, page_size: int = 25,
    source_ip: str | None = None, event_action: str | None = None,
):
    q = select(Event).order_by(Event.created_at.desc())
    if group_filter:
        q = q.where(Event.group_id == group_filter)
    if source_ip:
        q = q.where(Event.source_ip == source_ip)
    if event_action:
        q = q.where(Event.event_action == event_action)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[EventOut.model_validate(e) for e in result.scalars().all()])
