# server-api/app/api/routes/compliance.py
"""Compliance Manager surface — per-endpoint posture against common control
frameworks. See app/services/compliance.py for the evidence-gathering logic.
Read-only: this reports posture, it never writes."""
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Agent
from app.services import compliance

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/frameworks")
async def list_frameworks(_=Depends(get_current_user)):
    return compliance.list_frameworks()


@router.get("/endpoints")
async def list_endpoints(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    return await compliance.list_endpoints(db, group_filter)


@router.get("/endpoints/{agent_id}/frameworks/{framework_id}")
async def get_endpoint_framework(
    agent_id: str,
    framework_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    if framework_id not in compliance.FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Unknown framework")
    agent = await db.get(Agent, agent_id)
    if not agent or (group_filter and agent.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return await compliance.evaluate_endpoint_framework(db, agent_id, framework_id)
