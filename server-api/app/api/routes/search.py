# server-api/app/api/routes/search.py
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, Case, User

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=2, max_length=100),
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    group_id: Annotated[Optional[str], Depends(get_scoped_group)] = None,
    _: User = Depends(get_current_user),
    limit: int = Query(default=5, le=20),
):
    """Search alerts and cases by title, source IP, or hostname."""
    pattern = f"%{q}%"

    alert_q = (
        select(Alert)
        .where(
            or_(
                Alert.title.ilike(pattern),
                Alert.source_ip.ilike(pattern),
                Alert.hostname.ilike(pattern),
            )
        )
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if group_id:
        alert_q = alert_q.where(Alert.group_id == group_id)
    alerts = (await db.execute(alert_q)).scalars().all()

    case_q = (
        select(Case)
        .where(
            or_(
                Case.title.ilike(pattern),
                Case.description.ilike(pattern),
            )
        )
        .order_by(Case.created_at.desc())
        .limit(limit)
    )
    if group_id:
        case_q = case_q.where(Case.group_id == group_id)
    cases = (await db.execute(case_q)).scalars().all()

    return {
        "alerts": [
            {
                "id": str(a.id),
                "type": "alert",
                "title": a.title,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "cases": [
            {
                "id": str(c.id),
                "type": "case",
                "title": c.title,
                "status": c.status,
                "severity": c.severity,
                "created_at": c.created_at.isoformat(),
            }
            for c in cases
        ],
    }
