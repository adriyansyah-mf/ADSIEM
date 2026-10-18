# server-api/app/api/routes/agents.py
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import or_, select, update
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group, fetch_scoped, assert_group_access
from app.core.security import generate_agent_token, hash_token
from app.models.models import Agent, AgentLogSource, AgentTask, EnrollmentToken, User
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
    ".zip": "application/zip",
    ".msi": "application/x-msi",
}
# Names written by agent/packaging/build-{deb,rpm,windows}.sh and build-msi.ps1
_PACKAGE_NAMES = [
    ("deb", re.compile(r"^siem-agent_(?P<version>[^_]+)_(?P<arch>[^_.]+)\.deb$")),
    ("rpm", re.compile(r"^siem-agent-(?P<version>[^-]+)-[^.]+\.(?P<arch>[^.]+)\.rpm$")),
    ("windows", re.compile(r"^siem-agent-windows-(?P<arch>[^-]+)-(?P<version>.+)\.zip$")),
    ("msi", re.compile(r"^siem-agent-(?P<version>\d[\d.]*)-(?P<arch>x64)\.msi$")),  # build-msi.ps1
]


def _parse_package(name: str) -> dict | None:
    for pkg_type, rx in _PACKAGE_NAMES:
        if m := rx.match(name):
            return {"type": pkg_type, "version": m.group("version"), "arch": m.group("arch")}
    return None


def _list_packages() -> list[dict]:
    if not PACKAGES_DIR.exists():
        return []
    pkgs = []
    for f in sorted(PACKAGES_DIR.iterdir()):
        meta = _parse_package(f.name)
        if f.suffix not in _MEDIA_TYPES or meta is None:
            continue
        pkgs.append({"filename": f.name, **meta, "size_bytes": f.stat().st_size})
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
    if not path.exists() or path.suffix not in _MEDIA_TYPES or _parse_package(filename) is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return FileResponse(
        path=str(path),
        media_type=_MEDIA_TYPES[path.suffix],
        filename=filename,
    )

@router.get("/api/agents", response_model=PaginatedResponse)
async def list_agents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    page: int = 1, page_size: int = 25,
    search: str | None = None,
    status: str | None = None,
):
    from sqlalchemy import func, or_
    q = select(Agent).options(selectinload(Agent.log_sources))
    if group_filter:
        q = q.where(Agent.group_id == group_filter)
    if search:
        like = f"%{search}%"
        q = q.where(or_(Agent.name.ilike(like), Agent.hostname.ilike(like)))
    if status:
        q = q.where(Agent.status == status)
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
    # Authorization: a per-token row (hashed, expirable, limited or unlimited
    # uses) first; the legacy global token is a fallback only when configured.
    group_id, token_row = await _resolve_enrollment_token(db, body.enrollment_token)
    needs_approval = bool(token_row and token_row.require_approval)

    raw_token = generate_agent_token()
    # Upsert: reuse the existing agent for the same hostname+group so a rebuilt
    # host doesn't leave a duplicate behind...
    result = await db.execute(
        select(Agent).options(selectinload(Agent.log_sources))
        .where(Agent.hostname == body.hostname, Agent.group_id == group_id)
        .order_by(Agent.enrolled_at.desc())
        .limit(1)
    )
    agent = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    # ...but never while that agent is still connected: anyone holding a key
    # could otherwise claim a live agent's identity (and its live-response
    # tasks) just by reporting its hostname.
    if agent and agent.last_seen_at and now - agent.last_seen_at < REENROLL_AFTER:
        raise HTTPException(status_code=409, detail=(
            f"An agent named '{body.hostname}' is connected (last seen {int((now - agent.last_seen_at).total_seconds())}s ago). "
            f"Stop it, or remove it in the dashboard, to enroll this host in its place."))

    if token_row is not None:
        await _claim_enrollment_token(db, token_row)

    if agent:
        agent.name = body.name or agent.name
        agent.version = body.version
        agent.status = "online"
        agent.last_seen_at = now
        agent.token_hash = hash_token(raw_token)
        if needs_approval:
            agent.approved = False
        # Log sources are server-driven after enrollment, so without this a
        # re-enrolled agent (e.g. a rebuilt container) keeps its old list and
        # never tails paths added to its config. Add what's new; leave sources
        # an analyst added, disabled or retyped in the dashboard alone.
        known = {s.path for s in agent.log_sources}
        for src in body.log_sources:
            if src.path not in known:
                db.add(AgentLogSource(agent_id=agent.id, path=src.path, log_type=src.log_type,
                                      is_enabled=src.is_enabled))
    else:
        # last_seen_at must be set here: agent_monitor ages agents out by it, and
        # a NULL would leave an agent that never heartbeats "online" forever.
        agent = Agent(
            name=body.name or body.hostname, hostname=body.hostname,
            group_id=group_id, version=body.version,
            token_hash=hash_token(raw_token), status="online",
            last_seen_at=now, approved=not needs_approval,
        )
        db.add(agent)
        await db.flush()
        for src in body.log_sources:
            db.add(AgentLogSource(agent_id=agent.id, path=src.path, log_type=src.log_type, is_enabled=src.is_enabled))

    if token_row is not None:
        token_row.used_by_agent_id = agent.id

    await db.commit()
    background.add_task(audit_log, db, None, "agent_enrolled", "agent", str(agent.id),
                        {"hostname": body.hostname, "pending_approval": needs_approval,
                         "enrollment_token": str(token_row.id) if token_row else "legacy"})
    return EnrollResponse(agent_id=str(agent.id), agent_token=raw_token)


# A host can re-enroll under an existing agent's name once that agent has been
# silent this long (heartbeats come every 30 s).
REENROLL_AFTER = timedelta(minutes=2)


async def _resolve_enrollment_token(db: AsyncSession, presented: str) -> tuple[str, EnrollmentToken | None]:
    """Return (group_id, token_row) for a valid enrollment token, else raise 401.

    Doesn't consume a use; _claim_enrollment_token does, once enrollment goes ahead."""
    presented = (presented or "").strip()
    if not presented:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")

    token_hash = hashlib.sha256(presented.encode()).hexdigest()
    row = (await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
    )).scalar_one_or_none()
    if row is not None:
        if not row.is_active:
            raise HTTPException(status_code=401, detail="Enrollment token is no longer active")
        if row.max_uses is not None and (row.use_count or 0) >= row.max_uses:
            raise HTTPException(status_code=401, detail=_spent(row))
        if row.expires_at is not None and row.expires_at <= datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Enrollment token has expired")
        return row.group_id, row

    # Legacy global fallback — only when explicitly set (no insecure default).
    configured = (settings.AGENT_ENROLLMENT_TOKEN or "").strip()
    if configured and configured not in ("bootstrap-token",) and hmac.compare_digest(presented, configured):
        return "default", None

    raise HTTPException(status_code=401, detail="Invalid enrollment token")


def _spent(row: EnrollmentToken) -> str:
    return ("Enrollment token has already been used" if row.max_uses == 1
            else f"Enrollment token has reached its limit of {row.max_uses} agents")


async def _claim_enrollment_token(db: AsyncSession, row: EnrollmentToken) -> None:
    """Count one use, atomically: concurrent enrollments can't exceed max_uses."""
    claimed = (await db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == row.id,
               or_(EnrollmentToken.max_uses.is_(None), EnrollmentToken.use_count < EnrollmentToken.max_uses))
        .values(use_count=EnrollmentToken.use_count + 1, used_at=datetime.now(timezone.utc))
        .returning(EnrollmentToken.id)
    )).scalar_one_or_none()
    if claimed is None:
        raise HTTPException(status_code=401, detail=_spent(row))


@router.post("/api/agents/{agent_id}/approve", response_model=AgentOut)
async def approve_agent(
    agent_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Let a pending agent (enrolled with a key that requires approval) ship logs and take tasks."""
    agent = await fetch_scoped(
        db, Agent, agent_id, group_filter,
        options=[selectinload(Agent.log_sources)], detail="Agent not found",
    )
    agent.approved = True
    await db.commit()
    await db.refresh(agent)
    background.add_task(audit_log, db, current_user.id, "agent_approved", "agent", str(agent_id),
                        {"hostname": agent.hostname})
    return AgentOut.model_validate(agent)

@router.get("/api/agents/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(
        db, Agent, agent_id, group_filter,
        options=[selectinload(Agent.log_sources)], detail="Agent not found",
    )
    return AgentOut.model_validate(agent)

@router.put("/api/agents/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: UUID, body: AgentUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(
        db, Agent, agent_id, group_filter,
        options=[selectinload(Agent.log_sources)], detail="Agent not found",
    )
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "agent_revoked", "agent", str(agent_id))

# ─── Log Sources ─────────────────────────────────────────────────

@router.get("/api/agents/{agent_id}/log-sources", response_model=list[LogSourceOut])
async def get_log_sources(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    result = await db.execute(select(AgentLogSource).where(AgentLogSource.agent_id == agent_id))
    return [LogSourceOut.model_validate(s) for s in result.scalars().all()]

@router.post("/api/agents/{agent_id}/log-sources", response_model=LogSourceOut, status_code=201)
async def add_log_source(
    agent_id: UUID, body: LogSourceIn,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    agent.is_isolated = False
    task = AgentTask(agent_id=agent_id, task_type="unisolate_host", params={}, created_by=current_user.id)
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
