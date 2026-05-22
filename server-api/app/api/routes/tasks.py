# server-api/app/api/routes/tasks.py
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user
from app.models.models import Agent, AgentTask, FleetHunt
from app.schemas.schemas import (
    AgentTaskCreate, AgentTaskOut, AgentTaskResultIn,
    FleetHuntCreate, FleetHuntOut,
)

router = APIRouter(prefix="/api/tasks", tags=["tasks"])
fleet_router = APIRouter(prefix="/api/fleet-hunts", tags=["fleet-hunts"])


# ─── Agent Tasks ─────────────────────────────────────────────────

@router.get("", response_model=list[AgentTaskOut])
async def list_tasks(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
    agent_id: UUID | None = None,
    status: str | None = None,
    limit: int = 50,
):
    q = select(AgentTask).order_by(AgentTask.created_at.desc()).limit(limit)
    if agent_id:
        q = q.where(AgentTask.agent_id == agent_id)
    if status:
        q = q.where(AgentTask.status == status)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{task_id}", response_model=AgentTaskOut)
async def get_task(
    task_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    t = (await db.execute(select(AgentTask).where(AgentTask.id == task_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Task not found")
    return t


@router.post("", response_model=AgentTaskOut, status_code=201)
async def create_task(
    body: AgentTaskCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(get_current_user),
):
    if body.agent_id:
        agent = (await db.execute(select(Agent).where(Agent.id == body.agent_id))).scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "Agent not found")
    task = AgentTask(
        agent_id=body.agent_id,
        task_type=body.task_type,
        params=body.params,
        created_by=user.id,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return task


@router.delete("/{task_id}", status_code=204)
async def delete_task(
    task_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    t = (await db.execute(select(AgentTask).where(AgentTask.id == task_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Task not found")
    await db.delete(t)
    await db.commit()


# ─── Agent-facing: submit result ─────────────────────────────────

@router.post("/{task_id}/result", status_code=204)
async def submit_result(
    task_id: UUID,
    body: AgentTaskResultIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent=Depends(get_agent),
):
    t = (await db.execute(
        select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Task not found")
    now = datetime.now(timezone.utc)
    await db.execute(
        update(AgentTask).where(AgentTask.id == task_id).values(
            status=body.status,
            result=body.result,
            error=body.error,
            completed_at=now,
        )
    )
    # update fleet hunt progress
    if t.fleet_hunt_id and body.status in ("done", "failed"):
        fh = (await db.execute(select(FleetHunt).where(FleetHunt.id == t.fleet_hunt_id))).scalar_one_or_none()
        if fh:
            new_completed = fh.completed_agents + 1
            new_status = "done" if new_completed >= fh.total_agents else "running"
            await db.execute(
                update(FleetHunt).where(FleetHunt.id == fh.id).values(
                    completed_agents=new_completed, status=new_status
                )
            )
    await db.commit()


# ─── Fleet Hunts ─────────────────────────────────────────────────

@fleet_router.get("", response_model=list[FleetHuntOut])
async def list_fleet_hunts(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    result = await db.execute(select(FleetHunt).order_by(FleetHunt.created_at.desc()))
    return result.scalars().all()


@fleet_router.get("/{hunt_id}", response_model=FleetHuntOut)
async def get_fleet_hunt(
    hunt_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    fh = (await db.execute(select(FleetHunt).where(FleetHunt.id == hunt_id))).scalar_one_or_none()
    if not fh:
        raise HTTPException(404, "Fleet hunt not found")
    return fh


@fleet_router.get("/{hunt_id}/tasks", response_model=list[AgentTaskOut])
async def get_fleet_hunt_tasks(
    hunt_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    result = await db.execute(
        select(AgentTask).where(AgentTask.fleet_hunt_id == hunt_id).order_by(AgentTask.created_at.desc())
    )
    return result.scalars().all()


@fleet_router.post("", response_model=FleetHuntOut, status_code=201)
async def create_fleet_hunt(
    body: FleetHuntCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(get_current_user),
):
    if body.agent_ids:
        agents = (await db.execute(select(Agent).where(Agent.id.in_(body.agent_ids)))).scalars().all()
    else:
        agents = (await db.execute(select(Agent).where(Agent.status == "online"))).scalars().all()
    if not agents:
        raise HTTPException(400, "No online agents found")

    fh = FleetHunt(
        name=body.name,
        description=body.description,
        task_type=body.task_type,
        params=body.params,
        total_agents=len(agents),
        created_by=user.id,
    )
    db.add(fh)
    await db.flush()

    for agent in agents:
        db.add(AgentTask(
            agent_id=agent.id,
            fleet_hunt_id=fh.id,
            task_type=body.task_type,
            params=body.params,
            created_by=user.id,
        ))

    await db.commit()
    await db.refresh(fh)
    return fh
