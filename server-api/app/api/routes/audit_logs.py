from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import AuditLog, User
from app.api.routes.cases import get_scoped_group

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("")
async def list_audit_logs(
    limit: int = Query(100, le=500),
    action: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        q = q.where(AuditLog.action == action)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "actor_id": str(r.actor_id) if r.actor_id else None,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "detail": r.detail,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
