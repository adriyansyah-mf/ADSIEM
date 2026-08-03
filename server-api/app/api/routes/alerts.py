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
from app.core.es_client import get_log as es_get_log
from app.core.geoip import lookup_country
from app.models.models import Alert, AlertNote, User
from app.schemas.schemas import (
    AlertNoteCreate, AlertNoteOut, AlertOut, AlertSourceLogOut, AlertUpdate,
    EventOut, PaginatedResponse, RawLogOut,
)
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
    assignee_id: UUID | None = None, source_ip: str | None = None,
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
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    items = []
    for a in result.scalars().all():
        out = AlertOut.model_validate(a)
        out.source_ip_country = lookup_country(a.source_ip)
        items.append(out)
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=items)


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
    out = AlertOut.model_validate(alert)
    out.source_ip_country = lookup_country(alert.source_ip)
    return out


@router.get("/{alert_id}/source-log", response_model=AlertSourceLogOut)
async def get_alert_source_log(
    alert_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(require_permission("alerts:read")),
):
    """The raw log line (and decoded event) that triggered this alert, so an
    analyst can verify the detection against the original source data."""
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert or (group_filter and alert.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.event_id:
        return AlertSourceLogOut(event=None, raw_log=None)

    doc = await es_get_log(str(alert.event_id))
    if not doc:
        return AlertSourceLogOut(event=None, raw_log=None)

    return AlertSourceLogOut(
        event=EventOut(
            id=doc["id"],
            agent_id=doc.get("agent_id"),
            group_id=doc.get("group_id", "default"),
            decoded_fields=doc.get("decoded_fields") or {},
            event_category=doc.get("event_category"),
            event_action=doc.get("event_action"),
            source_ip=doc.get("source_ip"),
            user_name=doc.get("user_name"),
            created_at=doc["created_at"],
        ),
        raw_log=RawLogOut(
            id=doc["id"],
            agent_id=doc.get("agent_id"),
            log_type=doc.get("log_type"),
            raw_message=doc.get("raw_message", ""),
            received_at=doc["created_at"],
        ),
    )


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
