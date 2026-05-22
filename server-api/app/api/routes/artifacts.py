# server-api/app/api/routes/artifacts.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentTask, Artifact
from app.schemas.schemas import ArtifactCreate, ArtifactOut, ArtifactRunRequest, AgentTaskOut

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])

BUILTIN_ARTIFACTS = [
    {"name": "Process List", "description": "List all running processes with PID, name, cmdline, memory", "task_type": "process_list", "default_params": {}},
    {"name": "Network Connections", "description": "Active TCP/UDP connections and listening ports", "task_type": "netstat", "default_params": {}},
    {"name": "Persistence Check", "description": "Scan common persistence locations: crontabs, init scripts, systemd units, SSH keys, sudoers", "task_type": "persistence_check", "default_params": {}},
    {"name": "User Accounts", "description": "List local user accounts from /etc/passwd", "task_type": "users_list", "default_params": {}},
    {"name": "Kernel Log Tail", "description": "Last 200 kernel/dmesg log lines", "task_type": "dmesg_tail", "default_params": {"lines": 200}},
    {"name": "Open Files", "description": "List open file descriptors per process", "task_type": "open_files", "default_params": {"limit": 50}},
    {"name": "File List", "description": "List files in a directory with metadata", "task_type": "file_list", "default_params": {"path": "/tmp", "max_depth": 2}},
    {"name": "File Acquisition", "description": "Download a specific file from the endpoint for forensic analysis", "task_type": "file_get", "default_params": {"path": ""}},
    {"name": "YARA Scan", "description": "Scan a path with all enabled YARA rules", "task_type": "yara_scan", "default_params": {"path": "/tmp", "recursive": True}},
]


@router.get("", response_model=list[ArtifactOut])
async def list_artifacts(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    result = await db.execute(select(Artifact).order_by(Artifact.name))
    return result.scalars().all()


@router.post("", response_model=ArtifactOut, status_code=201)
async def create_artifact(
    body: ArtifactCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    art = Artifact(**body.model_dump())
    db.add(art)
    await db.commit()
    await db.refresh(art)
    return art


@router.put("/{artifact_id}", response_model=ArtifactOut)
async def update_artifact(
    artifact_id: UUID,
    body: ArtifactCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    art = (await db.execute(select(Artifact).where(Artifact.id == artifact_id))).scalar_one_or_none()
    if not art:
        raise HTTPException(404, "Artifact not found")
    for k, v in body.model_dump().items():
        setattr(art, k, v)
    await db.commit()
    await db.refresh(art)
    return art


@router.delete("/{artifact_id}", status_code=204)
async def delete_artifact(
    artifact_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    art = (await db.execute(select(Artifact).where(Artifact.id == artifact_id))).scalar_one_or_none()
    if not art:
        raise HTTPException(404, "Artifact not found")
    await db.delete(art)
    await db.commit()


@router.post("/{artifact_id}/run", response_model=list[AgentTaskOut], status_code=201)
async def run_artifact(
    artifact_id: UUID,
    body: ArtifactRunRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(get_current_user),
):
    art = (await db.execute(select(Artifact).where(Artifact.id == artifact_id))).scalar_one_or_none()
    if not art:
        raise HTTPException(404, "Artifact not found")

    params = body.params if body.params is not None else art.default_params

    if body.agent_ids:
        agents = (await db.execute(select(Agent).where(Agent.id.in_(body.agent_ids)))).scalars().all()
    else:
        agents = (await db.execute(select(Agent).where(Agent.status == "online"))).scalars().all()

    if not agents:
        raise HTTPException(400, "No agents available")

    tasks = []
    for agent in agents:
        t = AgentTask(agent_id=agent.id, task_type=art.task_type, params=params, created_by=user.id)
        db.add(t)
        tasks.append(t)

    await db.commit()
    for t in tasks:
        await db.refresh(t)
    return tasks


@router.get("/builtins", response_model=list[dict])
async def list_builtins(_=Depends(get_current_user)):
    return BUILTIN_ARTIFACTS
