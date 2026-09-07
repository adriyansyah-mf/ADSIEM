# server-api/app/core/deps.py
from dataclasses import dataclass
from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import decode_token, hash_token
from app.models.models import Agent, Role, User
from app.services.api_keys import KEY_PREFIX_MARKER, authenticate_api_key

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class _ServiceRole:
    name: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class ServicePrincipal:
    """Identity resolved from an `adsiem_` API key, structurally compatible with `User`
    for `require_permission`/`get_scoped_group` consumption. `id` is always None: an
    API key has no corresponding `users` row, and every FK column that stores the
    acting identity (`created_by`, `author_id`, `actor_id`, ...) is nullable for
    exactly this reason.
    """

    api_key_id: object
    group_id: str
    role: _ServiceRole
    id: None = None
    is_active: bool = True


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User | ServicePrincipal:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if credentials.credentials.startswith(KEY_PREFIX_MARKER):
        api_key = await authenticate_api_key(db, credentials.credentials)
        if api_key is None:
            raise HTTPException(status_code=401, detail="Invalid or expired API key")
        return ServicePrincipal(
            api_key_id=api_key.id,
            group_id=api_key.group_id,
            role=_ServiceRole(name="service_account", permissions=frozenset(api_key.permissions or [])),
        )

    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(
        select(User).options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == user_id, User.is_active.is_(True))
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
        # `.name` for real ORM Permission rows; a service principal's role carries
        # plain permission-name strings directly (see ServicePrincipal above).
        perms = {getattr(p, "name", p) for p in current_user.role.permissions}
        if permission_name not in perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return checker

def get_scoped_group(current_user: Annotated[User, Depends(get_current_user)]) -> str | None:
    if current_user.role.name == "superadmin":
        return None  # no filter
    return current_user.group_id


def require_resource_group(resource_group: str | None, scoped_group: str | None) -> None:
    if resource_group is None or (
        scoped_group is not None and resource_group != scoped_group
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

async def get_agent(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Agent:
    token = request.headers.get("X-Agent-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    token_hash = hash_token(token)
    result = await db.execute(select(Agent).where(Agent.token_hash == token_hash))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent
