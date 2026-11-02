# server-api/app/api/routes/policies.py
"""Group protection policies (services/agent_policy.py): the operator API
and the agents' fetch."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, AgentPolicy, User
from app.services import agent_policy
from app.services.audit import audit_log

router = APIRouter(prefix="/api/policies", tags=["policies"])
agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])


def _check_scope(group_id: str, scope: str | None) -> None:
    if scope is not None and group_id != scope:
        raise HTTPException(404, "Group not found")


@router.get("")
async def list_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    _: Annotated[User, Depends(get_current_user)],
):
    """Every group with agents or a policy: agent count and which policy applies."""
    counts = dict((await db.execute(select(Agent.group_id, func.count()).group_by(Agent.group_id))).all())
    policies = {p.group_id: p for p in (await db.execute(select(AgentPolicy))).scalars().all()}
    groups = sorted(set(counts) | set(policies) | {agent_policy.DEFAULT_GROUP})
    out = []
    for g in groups:
        if scope is not None and g != scope:
            continue
        eff = await agent_policy.effective(db, g)
        p = policies.get(g)
        out.append({"group": g, "agents": counts.get(g, 0), "own_policy": p is not None,
                    "applies": eff["group"], "version": eff["version"],
                    "updated_by": p.updated_by if p else None,
                    "updated_at": p.updated_at.isoformat() if p and p.updated_at else None})
    return out


@router.get("/{group_id}")
async def get_policy(
    group_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    _: Annotated[User, Depends(get_current_user)],
):
    _check_scope(group_id, scope)
    eff = await agent_policy.effective(db, group_id)
    return {"group": group_id, "applies": eff["group"], "own_policy": eff["group"] == group_id,
            "settings": eff["settings"], "version": eff["version"]}


@router.put("/{group_id}")
async def put_policy(
    group_id: str,
    body: agent_policy.PolicySettings,
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    _check_scope(group_id, scope)
    if not group_id.strip() or len(group_id) > 100:
        raise HTTPException(422, "group id: 1 to 100 characters")
    settings = body.model_dump()
    row = await db.get(AgentPolicy, group_id)
    who = getattr(user, "email", None) or user.username
    if row is None:
        row = AgentPolicy(group_id=group_id, settings=settings, revision=1, updated_by=who)
        db.add(row)
    else:
        row.settings, row.revision, row.updated_by = settings, row.revision + 1, who
    await db.commit()
    agent_policy.invalidate()
    await audit_log(db, user.id, "agent_policy_updated", "agent_policy", group_id,
                    {"version": agent_policy.version_of(settings), "exclusions": len(settings["exclusions"])})
    return await get_policy(group_id, db, scope, user)


@router.delete("/{group_id}", status_code=204)
async def delete_policy(
    group_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    scope: Annotated[str | None, Depends(get_scoped_group)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
):
    """The group goes back to the default group's policy."""
    _check_scope(group_id, scope)
    row = await db.get(AgentPolicy, group_id)
    if row is None:
        raise HTTPException(404, "No policy for this group")
    await db.delete(row)
    await db.commit()
    agent_policy.invalidate()
    await audit_log(db, user.id, "agent_policy_deleted", "agent_policy", group_id, {})


@agent_router.post("/policy")
async def agent_policy_fetch(
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    return await agent_policy.effective(db, agent.group_id)
