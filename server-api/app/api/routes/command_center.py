# server-api/app/api/routes/command_center.py
"""Command Center backend surface — currently just the AI Situation Brief.
Priority Queue, Operational Health, and Exposure/Coverage are composed on the
frontend from existing alerts/metrics/agent/UEBA/MITRE endpoints per the
Ironwatch spec's own Phase 2 dependency note, so no new endpoint is needed
for those — only the genuinely new AI summary capability lives here."""
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.services.situation_brief import get_situation_brief

router = APIRouter(prefix="/api/command-center", tags=["command-center"])


@router.get("/situation-brief")
async def situation_brief(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    force: bool = False,
):
    return await get_situation_brief(db, group_filter, force=force)
