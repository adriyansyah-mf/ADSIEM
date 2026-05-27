# server-api/app/api/routes/agents.py
import hashlib
import os
from pathlib import Path
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group
from app.core.security import generate_agent_token, hash_token
from app.models.models import Agent, AgentLogSource, AgentTask, EnrollmentToken, User
from app.models.models import now_utc
from app.schemas.schemas import (
    AgentOut, AgentUpdate, EnrollRequest, EnrollResponse,
    LogSourceIn, LogSourceOut, PaginatedResponse
)
from app.services.audit import audit_log

router = APIRouter(tags=["agents"])
Perm = require_permission("agents:manage")

PACKAGES_DIR = Path(os.environ.get("PACKAGES_DIR", "/app/packages"))

_MEDIA_TYPES = {
    ".deb": "application/vnd.debian.binary-package",
    ".rpm": "application/x-rpm",
}

import re as _re

def _parse_version(filename: str) -> str | None:
    """Extract version from filenames like siem-agent_1.1.0_amd64.deb or siem-agent-1.1.0-amd64."""
    m = _re.search(r'siem-agent[_-](\d+\.\d+\.\d+)', filename)
    return m.group(1) if m else None

def _find_latest_binary() -> tuple[str, str] | None:
    """Return (filename, version) of the latest raw binary, or None."""
    if not PACKAGES_DIR.exists():
        return None
    candidates = []
    for f in PACKAGES_DIR.iterdir():
        if f.suffix in _MEDIA_TYPES or not f.name.startswith("siem-agent-"):
            continue
        ver = _parse_version(f.name)
        if ver:
            candidates.append((f.name, ver))
    if not candidates:
        return None
    candidates.sort(key=lambda x: [int(p) for p in x[1].split(".")], reverse=True)
    return candidates[0]

def _list_packages() -> list[dict]:
    if not PACKAGES_DIR.exists():
        return []
    pkgs = []
    for f in sorted(PACKAGES_DIR.iterdir()):
        if f.suffix not in _MEDIA_TYPES:
            continue
        stat = f.stat()
        pkg_type = "deb" if f.suffix == ".deb" else "rpm"
        pkgs.append({
            "filename": f.name,
            "type": pkg_type,
            "size_bytes": stat.st_size,
        })
    return pkgs


@router.get("/api/agents/packages")
async def list_packages(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return _list_packages()


@router.get("/api/agents/packages/{filename}")
async def download_package(
    filename: str,
):
    # Prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = PACKAGES_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Package not found")
    # Packaged installers or raw binary
    media_type = _MEDIA_TYPES.get(path.suffix, "application/octet-stream")
    return FileResponse(
        path=str(path),
        media_type=media_type,
        filename=filename,
    )

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
    # Validate enrollment token: DB-issued tokens take priority, then static env token.
    # If no token provided, open enrollment is allowed (group comes from request).
    db_token = None
    if body.enrollment_token:
        token_result = await db.execute(
            select(EnrollmentToken).where(
                EnrollmentToken.token_hash == hash_token(body.enrollment_token),
                EnrollmentToken.is_active == True,
            )
        )
        db_token = token_result.scalar_one_or_none()

    if db_token:
        if db_token.expires_at and db_token.expires_at < now_utc():
            db_token.is_active = False
            await db.commit()
            raise HTTPException(status_code=401, detail="Enrollment token has expired")
        effective_group = db_token.group_id
    elif not body.enrollment_token or body.enrollment_token == settings.AGENT_ENROLLMENT_TOKEN:
        effective_group = body.group
    else:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")

    raw_token = generate_agent_token()
    # Upsert: reuse existing agent for same hostname+group to prevent duplicates on re-enrollment
    result = await db.execute(
        select(Agent).options(selectinload(Agent.log_sources))
        .where(Agent.hostname == body.hostname, Agent.group_id == effective_group)
        .order_by(Agent.enrolled_at.desc())
        .limit(1)
    )
    agent = result.scalar_one_or_none()
    if agent:
        agent.name = body.name or agent.name
        agent.version = body.version
        agent.status = "online"
        agent.token_hash = hash_token(raw_token)
    else:
        agent = Agent(
            name=body.name, hostname=body.hostname,
            group_id=effective_group, version=body.version,
            token_hash=hash_token(raw_token), status="online",
        )
        db.add(agent)
        await db.flush()
        for src in body.log_sources:
            db.add(AgentLogSource(agent_id=agent.id, path=src.path, log_type=src.log_type, is_enabled=src.is_enabled))

    # Mark DB token as used (one-time)
    if db_token:
        db_token.is_active = False
        db_token.used_at = now_utc()
        db_token.used_by_agent_id = agent.id

    await db.commit()
    background.add_task(audit_log, db, None, "agent_enrolled", "agent", str(agent.id), {"hostname": body.hostname})
    return EnrollResponse(agent_id=str(agent.id), agent_token=raw_token)

@router.get("/api/agents/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Agent).options(selectinload(Agent.log_sources)).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentOut.model_validate(agent)

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


@router.post("/api/agents/{agent_id}/isolate", response_model=AgentOut)
async def isolate_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if agent.status != "online":
        raise HTTPException(400, "Agent is not online")
    agent.is_isolated = True
    task = AgentTask(agent_id=agent_id, task_type="isolate_host", params={}, created_by=current_user.id)
    db.add(task)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.delete("/api/agents/{agent_id}/isolate", response_model=AgentOut)
async def unisolate_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(404, "Agent not found")
    agent.is_isolated = False
    task = AgentTask(agent_id=agent_id, task_type="unisolate_host", params={}, created_by=current_user.id)
    db.add(task)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.post("/api/agents/{agent_id}/upgrade", status_code=202)
async def upgrade_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if agent.status != "online":
        raise HTTPException(400, "Agent is not online")

    latest = _find_latest_binary()
    if not latest:
        raise HTTPException(404, "No upgrade binary available")

    filename, version = latest
    download_url = f"/api/agents/packages/{filename}"
    task = AgentTask(
        agent_id=agent_id,
        task_type="upgrade_agent",
        params={"download_url": download_url, "version": version},
        created_by=current_user.id,
    )
    db.add(task)
    await db.commit()
    return {"queued": True, "version": version, "download_url": download_url}
