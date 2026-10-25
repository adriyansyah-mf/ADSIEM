# server-api/app/api/routes/enrollment_tokens.py
import secrets
from datetime import timedelta
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.core.security import hash_token
from app.models.models import EnrollmentToken, User, now_utc
from app.schemas.schemas import EnrollmentTokenCreate, EnrollmentTokenCreated, EnrollmentTokenOut

router = APIRouter(tags=["enrollment-tokens"])
Perm = require_permission("agents:manage")


@router.post("/api/enrollment-tokens", response_model=EnrollmentTokenCreated, status_code=201)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    raw = secrets.token_urlsafe(32)
    expires = now_utc() + timedelta(hours=body.expires_hours) if body.expires_hours > 0 else None
    token = EnrollmentToken(
        token_hash=hash_token(raw),
        label=body.label,
        group_id=body.group_id,
        expires_at=expires,
        created_by=current_user.id,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    out = EnrollmentTokenOut.model_validate(token)
    return EnrollmentTokenCreated(**out.model_dump(), token=raw)


@router.get("/api/enrollment-tokens", response_model=list[EnrollmentTokenOut])
async def list_enrollment_tokens(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(
        select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc())
    )
    return [EnrollmentTokenOut.model_validate(t) for t in result.scalars().all()]


@router.delete("/api/enrollment-tokens/{token_id}", status_code=204)
async def revoke_enrollment_token(
    token_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(EnrollmentToken).where(EnrollmentToken.id == token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(404, "Token not found")
    token.is_active = False
    await db.commit()
