# server-api/app/api/routes/alerts.py
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Alert, AlertNote, User
from app.schemas.schemas import AlertNoteCreate, AlertNoteOut, AlertOut, AlertUpdate, PaginatedResponse
from app.services.audit import audit_log

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_RESOLVED_STATUSES = {"resolved", "closed", "false_positive"}


@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(require_permission("alerts:read")),
    page: int = 1, page_size: int = 25,
    status: str | None = None, severity: str | None = None,
    assignee_id: UUID | None = None,
):
    q = select(Alert).options(selectinload(Alert.notes)).order_by(Alert.created_at.desc())
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if assignee_id:
        q = q.where(Alert.assignee_id == assignee_id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[AlertOut.model_validate(a) for a in result.scalars().all()])


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(require_permission("alerts:read")),
):
    result = await db.execute(
        select(Alert).options(selectinload(Alert.notes)).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert or (group_filter and alert.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(alert)


@router.put("/{alert_id}")
async def update_alert(
    alert_id: UUID, body: AlertUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:update"))],
):
    result = await db.execute(
        select(Alert).options(selectinload(Alert.notes)).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.now(timezone.utc)
    new_status = body.status

    # SLA timestamps
    if new_status and alert.status == "new" and new_status != "new":
        if alert.acknowledged_at is None:
            alert.acknowledged_at = now
    if new_status and new_status in _RESOLVED_STATUSES and alert.resolved_at is None:
        alert.resolved_at = now

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(alert, field, value)

    await db.commit()
    await db.refresh(alert)
    background.add_task(audit_log, db, current_user.id, "alert_updated", "alert", str(alert_id),
                        {"status": body.status})

    out = AlertOut.model_validate(alert)
    response: dict = out.model_dump()

    # FP suggestion: if marking as false_positive, hint a suppression target
    if new_status == "false_positive":
        suggestion = None
        if alert.source_ip:
            suggestion = {"entity_type": "ip", "entity_value": alert.source_ip}
        elif alert.hostname:
            suggestion = {"entity_type": "hostname", "entity_value": alert.hostname}
        else:
            suggestion = {"entity_type": "rule_title", "entity_value": alert.title}
        response["fp_suppression_suggestion"] = suggestion

    return response


@router.post("/{alert_id}/notes", response_model=AlertNoteOut, status_code=201)
async def add_note(
    alert_id: UUID, body: AlertNoteCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:update"))],
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Alert not found")
    note = AlertNote(alert_id=alert_id, author_id=current_user.id, content=body.content)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return AlertNoteOut.model_validate(note)
