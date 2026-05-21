from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user, require_permission
from app.models.models import Agent, HygieneSnapshot, User
from app.schemas.schemas import HygieneSnapshotIn, HygieneSnapshotOut

router = APIRouter(tags=["hygiene"])


@router.post("/api/hygiene", status_code=204)
async def ingest_hygiene(
    body: HygieneSnapshotIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_agent)],
):
    snap = HygieneSnapshot(
        agent_id=agent.id,
        hostname=body.hostname or agent.hostname,
        group_id=agent.group_id,
        os_name=body.os_name,
        os_version=body.os_version,
        kernel=body.kernel,
        arch=body.arch,
        uptime_seconds=body.uptime_seconds,
        cpu_count=body.cpu_count,
        mem_total_mb=body.mem_total_mb,
        mem_used_mb=body.mem_used_mb,
        disk_partitions=body.disk_partitions,
        open_ports=body.open_ports,
        users=body.users,
        hygiene_score=body.hygiene_score,
        issues=body.issues,
    )
    db.add(snap)
    await db.commit()


@router.get("/api/hygiene/latest", response_model=list[HygieneSnapshotOut])
async def get_latest_snapshots(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Latest snapshot per agent."""
    # Subquery: max collected_at per agent
    sub = (
        select(
            HygieneSnapshot.agent_id,
            func.max(HygieneSnapshot.collected_at).label("max_at"),
        )
        .group_by(HygieneSnapshot.agent_id)
        .subquery()
    )
    result = await db.execute(
        select(HygieneSnapshot)
        .join(sub, (HygieneSnapshot.agent_id == sub.c.agent_id) &
              (HygieneSnapshot.collected_at == sub.c.max_at))
        .order_by(desc(HygieneSnapshot.hygiene_score))
    )
    snaps = result.scalars().all()
    return [HygieneSnapshotOut(
        id=str(s.id),
        agent_id=str(s.agent_id),
        hostname=s.hostname,
        group_id=s.group_id,
        os_name=s.os_name,
        os_version=s.os_version,
        kernel=s.kernel,
        arch=s.arch,
        uptime_seconds=s.uptime_seconds,
        cpu_count=s.cpu_count,
        mem_total_mb=s.mem_total_mb,
        mem_used_mb=s.mem_used_mb,
        disk_partitions=s.disk_partitions or [],
        open_ports=s.open_ports or [],
        users=s.users or [],
        hygiene_score=s.hygiene_score,
        issues=s.issues or [],
        collected_at=s.collected_at,
    ) for s in snaps]


@router.get("/api/hygiene/{agent_id}", response_model=list[HygieneSnapshotOut])
async def get_agent_hygiene_history(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(HygieneSnapshot)
        .where(HygieneSnapshot.agent_id == agent_id)
        .order_by(desc(HygieneSnapshot.collected_at))
        .limit(24)
    )
    snaps = result.scalars().all()
    return [HygieneSnapshotOut(
        id=str(s.id),
        agent_id=str(s.agent_id),
        hostname=s.hostname,
        group_id=s.group_id,
        os_name=s.os_name,
        os_version=s.os_version,
        kernel=s.kernel,
        arch=s.arch,
        uptime_seconds=s.uptime_seconds,
        cpu_count=s.cpu_count,
        mem_total_mb=s.mem_total_mb,
        mem_used_mb=s.mem_used_mb,
        disk_partitions=s.disk_partitions or [],
        open_ports=s.open_ports or [],
        users=s.users or [],
        hygiene_score=s.hygiene_score,
        issues=s.issues or [],
        collected_at=s.collected_at,
    ) for s in snaps]
