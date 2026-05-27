# server-api/app/api/routes/audit_logs.py
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import AuditLog
from app.schemas.schemas import AuditLogOut, PaginatedResponse

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])
Perm = require_permission("settings:manage")  # admin-only


@router.get("", response_model=PaginatedResponse)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=1000),
    action: str | None = None,
    resource_type: str | None = None,
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.where(AuditLog.action == action)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[AuditLogOut.model_validate(r) for r in result.scalars().all()],
    )
