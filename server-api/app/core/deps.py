# server-api/app/core/deps.py
from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
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
    if current_user.role.name == "superadmin":
        return None  # no filter
    return current_user.group_id

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
