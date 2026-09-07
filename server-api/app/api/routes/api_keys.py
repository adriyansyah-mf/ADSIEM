# server-api/app/api/routes/api_keys.py
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.rate_limit import rate_limit_by_user_group
from app.models.models import ApiKey, User
from app.schemas.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.services.api_keys import (
    PermissionEscalationError,
    create_api_key,
    revoke_api_key,
    validate_requested_permissions,
)

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])

Perm = require_permission("api_keys:manage")
RateLimitCreate = rate_limit_by_user_group("api_key_creation")


def _caller_permissions(current_user: User) -> set[str]:
    return {getattr(p, "name", p) for p in current_user.role.permissions}


@router.get("", response_model=list[ApiKeyOut])
async def list_api_keys(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(ApiKey).order_by(ApiKey.created_at.desc())
    if group_filter is not None:
        query = query.where(ApiKey.group_id == group_filter)
    rows = (await db.execute(query)).scalars().all()
    return [ApiKeyOut.model_validate(row) for row in rows]


@router.post("", response_model=ApiKeyCreated, status_code=201)
async def create_key(
    body: ApiKeyCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    _rate_limit: Annotated[None, Depends(RateLimitCreate)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    caller_is_superadmin = current_user.role.name == "superadmin"
    try:
        validate_requested_permissions(
            set(body.permissions),
            _caller_permissions(current_user),
            caller_is_superadmin=caller_is_superadmin,
        )
    except PermissionEscalationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    group_id = group_filter if group_filter is not None else (body.group_id or current_user.group_id or "default")
    api_key, full_key = await create_api_key(
        db,
        name=body.name,
        permissions=body.permissions,
        group_id=group_id,
        expires_at=body.expires_at,
        created_by=current_user.id,
    )
    return ApiKeyCreated(**ApiKeyOut.model_validate(api_key).model_dump(), secret=full_key)


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(ApiKey).where(ApiKey.id == key_id)
    if group_filter is not None:
        query = query.where(ApiKey.group_id == group_filter)
    api_key = (await db.execute(query)).scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    await revoke_api_key(db, api_key)
