from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import AuditLog, User
from app.services.audit import UNSCOPED_GROUP, verify_audit_chain

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("")
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    limit: int = Query(100, le=500),
    action: Optional[str] = None,
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if group_filter is not None:
        q = q.where(AuditLog.group_id == group_filter)
    if action:
        q = q.where(AuditLog.action == action)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "actor_type": r.actor_type,
            "actor_id": str(r.actor_id) if r.actor_id else None,
            "group_id": r.group_id,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "detail": r.detail,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/verify")
async def get_audit_chain_verification(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("audit:verify"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: Optional[str] = Query(None, description="Superadmin only: which tenant chain to verify"),
):
    target_group = group_filter if group_filter is not None else (group_id or UNSCOPED_GROUP)
    result = await verify_audit_chain(db, target_group)
    return {
        "group_id": result.group_id,
        "verified": result.verified,
        "verified_count": result.verified_count,
        "total_count": result.total_count,
        "head_hash_prefix": result.head_hash_prefix,
        "broken_at_id": result.broken_at_id,
        "broken_at_timestamp": result.broken_at_timestamp.isoformat() if result.broken_at_timestamp else None,
    }
