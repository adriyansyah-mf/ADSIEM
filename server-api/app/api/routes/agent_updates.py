# server-api/app/api/routes/agent_updates.py
"""Agent self-update rollouts per group (services/agent_update.py)."""
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, AgentUpdatePolicy, User
from app.schemas.schemas import UpdatePolicyIn, UpdatePolicyOut
from app.services import agent_update
from app.services.audit import audit_log

router = APIRouter(tags=["agent-updates"])
Perm = require_permission("agents:manage")


def _scoped(group_id: str, group_filter: str | None) -> None:
    if group_filter is not None and group_id != group_filter:
        raise HTTPException(404, "Update policy not found")


async def _policy(db: AsyncSession, group_id: str, group_filter: str | None) -> AgentUpdatePolicy:
    _scoped(group_id, group_filter)
    policy = await db.get(AgentUpdatePolicy, group_id)
    if policy is None:
        raise HTTPException(404, "Update policy not found")
    return policy


async def _out(db: AsyncSession, policy: AgentUpdatePolicy) -> UpdatePolicyOut:
    out = UpdatePolicyOut.model_validate(policy)
    out.progress = await agent_update.progress(db, policy)
    return out


@router.get("/api/agent-updates/packages")
async def list_signed_packages(_: Annotated[User, Depends(get_current_user)]):
    return [{k: v for k, v in p.items() if k != "signed"} for p in agent_update.signed_packages()]


@router.get("/api/agent-updates/policies", response_model=list[UpdatePolicyOut])
async def list_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    q = select(AgentUpdatePolicy).order_by(AgentUpdatePolicy.group_id)
    if group_filter is not None:
        q = q.where(AgentUpdatePolicy.group_id == group_filter)
    return [await _out(db, p) for p in (await db.execute(q)).scalars().all()]


@router.put("/api/agent-updates/policies/{group_id}", response_model=UpdatePolicyOut)
async def set_policy(
    group_id: str, body: UpdatePolicyIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Set the group's target version. A new target starts over at ring 0."""
    _scoped(group_id, group_filter)
    if not any(p["version"] == body.target_version and agent_update.offerable(p)
               for p in agent_update.signed_packages()):
        raise HTTPException(422, f"No signed package for version {body.target_version} in the package directory")
    policy = await db.get(AgentUpdatePolicy, group_id)
    if policy is None:
        policy = AgentUpdatePolicy(group_id=group_id, target_version=body.target_version, stage=0, revision=1)
        db.add(policy)
    elif policy.target_version != body.target_version:
        policy.target_version, policy.stage, policy.revision = body.target_version, 0, policy.revision + 1
        policy.paused, policy.pause_reason = False, None
    policy.max_failures, policy.updated_by = body.max_failures, user.id
    await db.commit()
    await db.refresh(policy)
    background.add_task(audit_log, db, user.id, "agent_update_target_set", "agent_update_policy", group_id,
                        {"target_version": policy.target_version, "revision": policy.revision})
    return await _out(db, policy)


async def _transition(db, group_id, group_filter, user, background, action: str) -> UpdatePolicyOut:
    policy = await _policy(db, group_id, group_filter)
    if action == "advance":
        if policy.paused:
            raise HTTPException(409, "Rollout is paused: resume or retry first")
        if policy.stage >= max(agent_update.RINGS):
            raise HTTPException(409, "Rollout already covers every ring")
        policy.stage += 1
    elif action == "pause":
        policy.paused, policy.pause_reason = True, f"paused by {user.username}"
    elif action == "resume":
        policy.paused, policy.pause_reason = False, None
    elif action == "retry":
        # failed agents attempt again: a new revision resets their attempt count
        policy.revision += 1
        policy.paused, policy.pause_reason = False, None
    policy.updated_by = user.id
    await db.commit()
    await db.refresh(policy)
    background.add_task(audit_log, db, user.id, f"agent_update_{action}", "agent_update_policy", group_id,
                        {"target_version": policy.target_version, "stage": policy.stage, "revision": policy.revision})
    return await _out(db, policy)


@router.post("/api/agent-updates/policies/{group_id}/{action}", response_model=UpdatePolicyOut)
async def change_rollout(
    group_id: str, action: str, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    if action not in ("advance", "pause", "resume", "retry"):
        raise HTTPException(404, "Unknown rollout action")
    return await _transition(db, group_id, group_filter, user, background, action)


@router.delete("/api/agent-updates/policies/{group_id}", status_code=204)
async def delete_policy(
    group_id: str, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Stop offering updates to the group (agents keep the version they run)."""
    policy = await _policy(db, group_id, group_filter)
    await db.delete(policy)
    await db.commit()
    background.add_task(audit_log, db, user.id, "agent_update_policy_deleted", "agent_update_policy", group_id)


@router.get("/api/agent/update/package/{filename}")
async def download_update(filename: str, agent: Annotated[Agent, Depends(get_agent)]):
    """The package an update offer names, for the agent holding a token."""
    if not agent.approved:
        raise HTTPException(403, "Agent not approved")
    path = agent_update.package_path(filename)
    if path is None:
        raise HTTPException(404, "Package not found")
    return FileResponse(path=str(path), media_type="application/octet-stream", filename=filename)
