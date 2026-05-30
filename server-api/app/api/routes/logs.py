# server-api/app/api/routes/logs.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import RawLog
from app.schemas.schemas import PaginatedResponse, RawLogOut

router = APIRouter(prefix="/api/logs", tags=["logs"])
Perm = require_permission("logs:read")

@router.get("", response_model=PaginatedResponse)
async def list_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    page: int = 1, page_size: int = 25,
    log_type: str | None = None, search: str | None = None,
):
    q = select(RawLog).order_by(RawLog.received_at.desc())
    if log_type:
        q = q.where(RawLog.log_type == log_type)
    if search:
        q = q.where(RawLog.raw_message.ilike(f"%{search}%"))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[RawLogOut.model_validate(r) for r in result.scalars().all()])
