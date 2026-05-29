import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, User

router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/alerts/csv")
@router.get("/alerts")
async def export_alerts_csv(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(5000, le=10000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if group_id is not None:
        q = q.where(Alert.group_id == group_id)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)

    rows = (await db.execute(q)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "source_ip", "destination_ip",
                     "rule_title", "group_id", "created_at", "acknowledged_at", "resolved_at"])
    for a in rows:
        writer.writerow([
            str(a.id), a.title, a.severity, a.status,
            getattr(a, "source_ip", ""), getattr(a, "destination_ip", ""),
            getattr(a, "rule_title", ""), a.group_id,
            a.created_at.isoformat() if a.created_at else "",
            a.acknowledged_at.isoformat() if getattr(a, "acknowledged_at", None) else "",
            a.resolved_at.isoformat() if getattr(a, "resolved_at", None) else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )
