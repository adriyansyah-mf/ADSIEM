# server-api/app/api/routes/compliance.py
"""Compliance Manager surface — per-endpoint posture against common control
frameworks. See app/services/compliance.py for the evidence-gathering logic.
The framework routes are read-only (they report posture, never write); the
/custom routes below let an analyst attest to an org-specific control that
has no automated check."""
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, User
from app.schemas.schemas import (
    CustomComplianceControlIn,
    CustomComplianceControlOut,
    CustomComplianceControlUpdate,
)
from app.services import compliance
from app.services.audit import audit_log

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


async def _get_scoped_agent(db: AsyncSession, agent_id: str, group_filter: str | None) -> Agent:
    agent = await db.get(Agent, agent_id)
    if not agent or (group_filter and agent.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return agent


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
    await _get_scoped_agent(db, agent_id, group_filter)
    return await compliance.evaluate_endpoint_framework(db, agent_id, framework_id)


@router.get("/endpoints/{agent_id}/custom", response_model=list[CustomComplianceControlOut])
async def list_custom_controls(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    await _get_scoped_agent(db, agent_id, group_filter)
    return await compliance.list_custom_controls(db, agent_id)


@router.post("/endpoints/{agent_id}/custom", response_model=CustomComplianceControlOut, status_code=201)
async def create_custom_control(
    agent_id: str,
    body: CustomComplianceControlIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    current_user: Annotated[User, Depends(require_permission("compliance:manage"))],
):
    agent = await _get_scoped_agent(db, agent_id, group_filter)
    control = await compliance.create_custom_control(
        db, agent, body.model_dump(), created_by=current_user.id
    )
    background.add_task(
        audit_log, db, current_user, "custom_compliance_control_created", "compliance", str(control.id)
    )
    return control


@router.patch("/endpoints/{agent_id}/custom/{control_id}", response_model=CustomComplianceControlOut)
async def update_custom_control(
    agent_id: str,
    control_id: str,
    body: CustomComplianceControlUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    current_user: Annotated[User, Depends(require_permission("compliance:manage"))],
):
    await _get_scoped_agent(db, agent_id, group_filter)
    control = await compliance.get_custom_control(db, agent_id, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Custom control not found")
    control = await compliance.update_custom_control(db, control, body.model_dump())
    background.add_task(
        audit_log, db, current_user, "custom_compliance_control_updated", "compliance", str(control.id)
    )
    return control


@router.delete("/endpoints/{agent_id}/custom/{control_id}", status_code=204)
async def delete_custom_control(
    agent_id: str,
    control_id: str,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    current_user: Annotated[User, Depends(require_permission("compliance:manage"))],
):
    await _get_scoped_agent(db, agent_id, group_filter)
    control = await compliance.get_custom_control(db, agent_id, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Custom control not found")
    await compliance.delete_custom_control(db, control)
    background.add_task(
        audit_log, db, current_user, "custom_compliance_control_deleted", "compliance", control_id
    )
