import hashlib
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import EnrollmentToken, User

router = APIRouter(prefix="/api/enrollment-tokens", tags=["enrollment-tokens"])


class TokenIn(BaseModel):
    label: str = ""
    group_id: Optional[str] = None
    expires_at: Optional[datetime] = None


@router.get("")
async def list_tokens(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(EnrollmentToken).where(EnrollmentToken.is_active == True).order_by(EnrollmentToken.created_at.desc())
    if group_id is not None:
        q = q.where(EnrollmentToken.group_id == group_id)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "label": r.label,
            "group_id": r.group_id,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "is_active": r.is_active,
            "used_at": r.used_at.isoformat() if r.used_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("", status_code=201)
async def create_token(
    body: TokenIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    tok = EnrollmentToken(
        token_hash=token_hash,
        label=body.label,
        group_id=body.group_id or group_id or current_user.group_id or "default",
        expires_at=body.expires_at,
        created_by=current_user.id,
    )
    db.add(tok)
    await db.commit()
    await db.refresh(tok)
    return {"id": str(tok.id), "token": raw_token, "label": tok.label, "group_id": tok.group_id}


@router.delete("/{token_id}", status_code=204)
async def revoke_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    tok = await db.get(EnrollmentToken, uuid.UUID(token_id))
    if not tok:
        raise HTTPException(status_code=404, detail="Token not found")
    tok.is_active = False
    await db.commit()
