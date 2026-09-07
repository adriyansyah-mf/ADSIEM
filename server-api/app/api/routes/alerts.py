# server-api/app/api/routes/alerts.py
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.es_client import get_log as es_get_log
from app.core.geoip import lookup_country
from app.models.models import AiFeedback, Alert, AlertNote, User
from app.schemas.schemas import (
    AiFeedbackCreate, AiFeedbackOut, AlertNoteCreate, AlertNoteOut, AlertOut,
    AlertSourceLogOut, AlertUpdate, EventOut, PaginatedResponse, RawLogOut,
)
from app.services.audit import audit_log

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

FEEDBACK_REINDEX_QUEUE = "siem:rag:feedback-reindex"

async def _push_feedback_reindex(feedback_id: str) -> None:
    """Push feedback_id to Redis queue so the worker embeds it for RAG retrieval."""
    try:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush(FEEDBACK_REINDEX_QUEUE, feedback_id)
        await redis.aclose()
    except Exception:
        pass  # non-critical: feedback row is already saved regardless

_RESOLVED_STATUSES = {"resolved", "closed", "false_positive"}
_SLA_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440, "info": 2880}


def _apply_sla(out: AlertOut, created_at: datetime, severity: str, status: str) -> AlertOut:
    from datetime import timedelta
    due_at = created_at + timedelta(minutes=_SLA_MINUTES.get(severity, 240))
    out.sla_due_at = due_at
    out.sla_breached = status not in _RESOLVED_STATUSES and datetime.now(timezone.utc) > due_at
    return out


@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(require_permission("alerts:read")),
    page: int = 1, page_size: int = 25,
    status: str | None = None, severity: str | None = None,
    assignee_id: str | None = None, source_ip: str | None = None,
    hostname: str | None = None, search: str | None = None,
    start_time: datetime | None = None, end_time: datetime | None = None,
):
    q = select(Alert).options(selectinload(Alert.notes)).order_by(Alert.created_at.desc())
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if assignee_id == "unassigned":
        q = q.where(Alert.assignee_id.is_(None))
    elif assignee_id:
        try:
            q = q.where(Alert.assignee_id == UUID(assignee_id))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid assignee ID") from exc
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    if hostname:
        q = q.where(Alert.hostname.ilike(f"%{hostname}%"))
    if search:
        q = q.where(Alert.title.ilike(f"%{search}%"))
    if start_time:
        q = q.where(Alert.created_at >= start_time)
    if end_time:
        q = q.where(Alert.created_at <= end_time)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    items = []
    for a in result.scalars().all():
        out = _apply_sla(AlertOut.model_validate(a), a.created_at, a.severity, a.status)
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
    out = _apply_sla(AlertOut.model_validate(alert), alert.created_at, alert.severity, alert.status)
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Alert).options(selectinload(Alert.notes)).where(Alert.id == alert_id)
    if group_filter is not None:
        query = query.where(Alert.group_id == group_filter)
    result = await db.execute(query)
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
    background.add_task(audit_log, db, current_user, "alert_updated", "alert", str(alert_id),
                        {"status": body.status})

    out = _apply_sla(AlertOut.model_validate(alert), alert.created_at, alert.severity, alert.status)
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Alert).where(Alert.id == alert_id)
    if group_filter is not None:
        query = query.where(Alert.group_id == group_filter)
    result = await db.execute(query)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Alert not found")
    note = AlertNote(alert_id=alert_id, author_id=current_user.id, content=body.content)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return AlertNoteOut.model_validate(note)


@router.get("/{alert_id}/feedback", response_model=list[AiFeedbackOut])
async def list_alert_feedback(
    alert_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    _=Depends(require_permission("alerts:read")),
):
    alert_query = select(Alert.id).where(Alert.id == alert_id)
    if group_filter is not None:
        alert_query = alert_query.where(Alert.group_id == group_filter)
    if (await db.execute(alert_query)).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    result = await db.execute(
        select(AiFeedback)
        .where(AiFeedback.entity_type == "alert", AiFeedback.entity_id == alert_id)
        .order_by(AiFeedback.created_at.desc())
    )
    return [AiFeedbackOut.model_validate(f) for f in result.scalars().all()]


@router.post("/{alert_id}/feedback", response_model=AiFeedbackOut, status_code=201)
async def submit_alert_feedback(
    alert_id: UUID, body: AiFeedbackCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("alerts:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Alert).where(Alert.id == alert_id)
    if group_filter is not None:
        query = query.where(Alert.group_id == group_filter)
    alert = (await db.execute(query)).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    feedback = AiFeedback(
        entity_type="alert",
        entity_id=alert_id,
        context_text=alert.title,
        ai_verdict=alert.ai_verdict,
        rating=body.rating,
        correct_verdict=body.correct_verdict,
        note=body.note,
        group_id=alert.group_id,
        created_by=current_user.id,
    )
    db.add(feedback)
    await db.commit()
    await db.refresh(feedback)
    background.add_task(_push_feedback_reindex, str(feedback.id))
    return AiFeedbackOut.model_validate(feedback)
