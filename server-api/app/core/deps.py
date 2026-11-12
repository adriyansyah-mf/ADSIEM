# server-api/app/core/deps.py
from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.redis_client import get_redis
from app.core.security import decode_token, hash_token
from app.models.models import Agent, Permission, Role, User

bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(
        select(User).options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def require_permission(permission_name: str):
    async def checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        # superadmin bypasses all permission checks
        if current_user.role.name == "superadmin":
            return current_user
        perms = {p.name for p in current_user.role.permissions}
        if permission_name not in perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return checker

def get_scoped_group(current_user: Annotated[User, Depends(get_current_user)]) -> str | None:
    """The group a request is limited to; None (no filter) only for superadmin.

    Many list routes test the result for truthiness (`if group_filter:`), so a
    non-superadmin with an empty group would see every tenant. Refuse instead."""
    if current_user.role.name == "superadmin":
        return None  # no filter
    if not (current_user.group_id or "").strip():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account has no group")
    return current_user.group_id

def assert_group_access(obj, group_filter: str | None, *, detail: str = "Not found") -> None:
    """Raise 404 if a group-scoped object belongs to another group.

    Superadmin (group_filter is None) always passes. A 404 — not a 403 — is
    deliberate: it must not confirm the existence of another tenant's object.
    """
    if group_filter is not None and getattr(obj, "group_id", None) != group_filter:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

async def fetch_scoped(
    db: AsyncSession,
    model,
    obj_id,
    group_filter: str | None,
    *,
    options: list | None = None,
    detail: str = "Not found",
):
    """Load a row by primary key within the caller's group scope.

    Returns the ORM instance, or raises 404 when the row is missing OR belongs
    to another group. Use this instead of ``db.get()`` / a bare ``select`` in
    any single-resource route so group isolation cannot be forgotten.
    """
    stmt = select(model).where(model.id == obj_id)
    if group_filter is not None:
        stmt = stmt.where(model.group_id == group_filter)
    if options:
        stmt = stmt.options(*options)
    obj = (await db.execute(stmt)).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return obj

async def get_agent(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Agent:
    token = request.headers.get("X-Agent-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)
    # the previous token (after a rotation) works until its grace ends, so an
    # agent that missed the heartbeat carrying the new one isn't locked out
    result = await db.execute(select(Agent).where(or_(
        Agent.token_hash == token_hash,
        and_(Agent.prev_token_hash == token_hash, Agent.prev_token_expires_at > now),
    )))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    request.state.agent_token_slot = "current" if agent.token_hash == token_hash else "previous"
    return agent
