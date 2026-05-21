# server-api/app/api/routes/agents.py
import hashlib
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group
from app.core.security import generate_agent_token, hash_token
from app.models.models import Agent, AgentLogSource, User
from app.schemas.schemas import (
    AgentOut, AgentUpdate, EnrollRequest, EnrollResponse,
    LogSourceIn, LogSourceOut, PaginatedResponse
)
from app.services.audit import audit_log

router = APIRouter(tags=["agents"])
Perm = require_permission("agents:manage")

@router.get("/api/agents", response_model=PaginatedResponse)
async def list_agents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    page: int = 1, page_size: int = 25,
):
    from sqlalchemy import func
    q = select(Agent).options(selectinload(Agent.log_sources))
    if group_filter:
        q = q.where(Agent.group_id == group_filter)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    agents = result.scalars().all()
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[AgentOut.model_validate(a) for a in agents])

@router.post("/api/agent/enroll", response_model=EnrollResponse, status_code=201)
async def enroll_agent(
    body: EnrollRequest,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if body.enrollment_token != settings.AGENT_ENROLLMENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
    raw_token = generate_agent_token()
    agent = Agent(
        name=body.name, hostname=body.hostname,
        group_id=body.group, version=body.version,
        token_hash=hash_token(raw_token), status="online",
    )
    db.add(agent)
    await db.flush()
    for src in body.log_sources:
        db.add(AgentLogSource(agent_id=agent.id, path=src.path, log_type=src.log_type, is_enabled=src.is_enabled))
    await db.commit()
    background.add_task(audit_log, db, None, "agent_enrolled", "agent", str(agent.id), {"hostname": body.hostname})
    return EnrollResponse(agent_id=agent.id, agent_token=raw_token)

@router.put("/api/agents/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: UUID, body: AgentUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(Agent).options(selectinload(Agent.log_sources)).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(agent, field, value)
    await db.commit()
    await db.refresh(agent)
    background.add_task(audit_log, db, current_user.id, "agent_updated", "agent", str(agent_id))
    return AgentOut.model_validate(agent)

@router.delete("/api/agents/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "agent_revoked", "agent", str(agent_id))

# ─── Log Sources ─────────────────────────────────────────────────

@router.get("/api/agents/{agent_id}/log-sources", response_model=list[LogSourceOut])
async def get_log_sources(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(AgentLogSource).where(AgentLogSource.agent_id == agent_id))
    return [LogSourceOut.model_validate(s) for s in result.scalars().all()]

@router.post("/api/agents/{agent_id}/log-sources", response_model=LogSourceOut, status_code=201)
async def add_log_source(
    agent_id: UUID, body: LogSourceIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    src = AgentLogSource(agent_id=agent_id, path=body.path, log_type=body.log_type, is_enabled=body.is_enabled)
    db.add(src)
    await db.commit()
    await db.refresh(src)
    background.add_task(audit_log, db, current_user.id, "log_source_added", "agent_log_source", str(src.id), {"path": body.path})
    return LogSourceOut.model_validate(src)

@router.put("/api/agents/{agent_id}/log-sources/{source_id}", response_model=LogSourceOut)
async def update_log_source(
    agent_id: UUID, source_id: UUID, body: LogSourceIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.id == source_id, AgentLogSource.agent_id == agent_id)
    )
    src = result.scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Log source not found")
    for field, value in body.model_dump().items():
        setattr(src, field, value)
    await db.commit()
    await db.refresh(src)
    background.add_task(audit_log, db, current_user.id, "log_source_updated", "agent_log_source", str(source_id))
    return LogSourceOut.model_validate(src)

@router.delete("/api/agents/{agent_id}/log-sources/{source_id}", status_code=204)
async def delete_log_source(
    agent_id: UUID, source_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.id == source_id, AgentLogSource.agent_id == agent_id)
    )
    src = result.scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Log source not found")
    await db.delete(src)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "log_source_deleted", "agent_log_source", str(source_id))
