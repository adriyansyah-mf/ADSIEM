import hashlib
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import EnrollmentToken, User

router = APIRouter(prefix="/api/enrollment-tokens", tags=["enrollment-tokens"])


class TokenIn(BaseModel):
    label: str = ""
    group_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    # 1 = single-use (default); a number = that many agents; None = unlimited
    # (a deployment key for the install one-liner — revoke it when done)
    max_uses: Optional[int] = Field(default=1, ge=1)
    require_approval: bool = False


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
            "max_uses": r.max_uses,
            "use_count": r.use_count or 0,
            "require_approval": r.require_approval,
            "used_at": r.used_at.isoformat() if r.used_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("", status_code=201)
async def create_token(
    body: TokenIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents:manage")),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    tok = EnrollmentToken(
        token_hash=token_hash,
        label=body.label,
        # a group-scoped admin can only mint keys for their own group
        group_id=group_id if group_id is not None else (body.group_id or current_user.group_id or "default"),
        expires_at=body.expires_at,
        max_uses=body.max_uses,
        require_approval=body.require_approval,
        created_by=current_user.id,
    )
    db.add(tok)
    await db.commit()
    await db.refresh(tok)
    return {"id": str(tok.id), "token": raw_token, "label": tok.label, "group_id": tok.group_id,
            "max_uses": tok.max_uses, "require_approval": tok.require_approval}


@router.delete("/{token_id}", status_code=204)
async def revoke_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents:manage")),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(EnrollmentToken).where(EnrollmentToken.id == uuid.UUID(token_id))
    if group_id is not None:
        q = q.where(EnrollmentToken.group_id == group_id)
    tok = (await db.execute(q)).scalar_one_or_none()
    if not tok:
        raise HTTPException(status_code=404, detail="Token not found")
    tok.is_active = False
    await db.commit()
