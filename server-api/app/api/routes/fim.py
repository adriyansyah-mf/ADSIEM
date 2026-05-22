from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user
from app.models.models import Agent, FimEvent, FimWatchPath, User
from app.schemas.schemas import FimEventIn, FimEventOut, FimWatchPathCreate, FimWatchPathOut

router = APIRouter(tags=["fim"])


# ─── Watch Paths (dashboard config) ──────────────────────────────────────────

@router.get("/api/fim/paths", response_model=list[FimWatchPathOut])
async def list_fim_paths(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(FimWatchPath).order_by(FimWatchPath.path))
    return result.scalars().all()


@router.post("/api/fim/paths", response_model=FimWatchPathOut, status_code=201)
async def create_fim_path(
    body: FimWatchPathCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    existing = await db.execute(select(FimWatchPath).where(FimWatchPath.path == body.path))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Path already exists")
    p = FimWatchPath(path=body.path.rstrip("/") or "/")
    db.add(p)
    await db.commit()
    await db.refresh(p)
    return p


@router.patch("/api/fim/paths/{path_id}", response_model=FimWatchPathOut)
async def toggle_fim_path(
    path_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(FimWatchPath).where(FimWatchPath.id == path_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404)
    p.is_enabled = not p.is_enabled
    await db.commit()
    await db.refresh(p)
    return p


@router.delete("/api/fim/paths/{path_id}", status_code=204)
async def delete_fim_path(
    path_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(FimWatchPath).where(FimWatchPath.id == path_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404)
    await db.delete(p)
    await db.commit()


# ─── Event ingest (agent) ─────────────────────────────────────────────────────

@router.post("/api/fim", status_code=204)
async def ingest_fim(
    body: FimEventIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_agent)],
):
    for ev in body.events[:200]:
        detected_at = datetime.now(timezone.utc)
        if ev.detected_at:
            try:
                detected_at = datetime.fromisoformat(ev.detected_at.replace("Z", "+00:00"))
            except ValueError:
                pass
        db.add(FimEvent(
            agent_id=agent.id,
            group_id=agent.group_id,
            path=ev.path,
            event_type=ev.event_type,
            sha256=ev.sha256,
            size_bytes=ev.size_bytes,
            detected_at=detected_at,
        ))
    await db.commit()


# ─── Event query (dashboard) ──────────────────────────────────────────────────

@router.get("/api/fim/events", response_model=list[FimEventOut])
async def list_fim_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    agent_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    path_prefix: str | None = Query(default=None),
    limit: int = Query(default=200, le=1000),
):
    q = select(FimEvent).order_by(desc(FimEvent.detected_at)).limit(limit)
    if agent_id:
        q = q.where(FimEvent.agent_id == UUID(agent_id))
    if event_type:
        q = q.where(FimEvent.event_type == event_type.upper())
    if path_prefix:
        q = q.where(FimEvent.path.like(f"{path_prefix}%"))
    result = await db.execute(q)
    return result.scalars().all()
