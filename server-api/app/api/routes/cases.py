# server-api/app/api/routes/cases.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select, or_, func
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group, fetch_scoped
from app.models.models import AiFeedback, Alert, AlertNote, Case, CaseAlert, CaseNote, User
from app.schemas.schemas import (
    AiFeedbackCreate, AiFeedbackOut, CaseOut, CaseSummaryOut, CaseCreate, CaseUpdate,
    CaseNoteCreate, CaseNoteOut, PaginatedResponse,
)
from app.services.audit import audit_log
from app.core.config import settings
from app.api.routes.case_evidence import router as evidence_router
from worker.soar.case_outbox import CaseEvent, enqueue_case_event
import redis.asyncio as aioredis

router = APIRouter(tags=["cases"])
router.include_router(evidence_router)

async def _push_rag_reindex(case_id: str) -> None:
    """Push case_id to Redis reindex queue so worker indexes it immediately."""
    import structlog
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush("siem:rag:reindex", case_id)
        await redis.aclose()
    except Exception as exc:
        structlog.get_logger().warning("rag_reindex_push_failed", case_id=case_id, error=str(exc))

async def _push_feedback_reindex(feedback_id: str) -> None:
    """Push feedback_id to Redis queue so the worker embeds it for RAG retrieval."""
    import structlog
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush("siem:rag:feedback-reindex", feedback_id)
        await redis.aclose()
    except Exception as exc:
        structlog.get_logger().warning("feedback_reindex_push_failed", feedback_id=feedback_id, error=str(exc))

# A campaign case can carry hundreds of AI notes; the case page gets the newest
# CASE_NOTES_LIMIT and pages older ones through GET /api/cases/{id}/notes.
CASE_NOTES_LIMIT = 100


async def _case_out(db: AsyncSession, case: Case) -> CaseOut:
    notes = (await db.execute(
        select(CaseNote).where(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.desc(), CaseNote.id.desc()).limit(CASE_NOTES_LIMIT)
    )).scalars().all()
    total = (await db.execute(
        select(func.count()).select_from(CaseNote).where(CaseNote.case_id == case.id)
    )).scalar_one()
    set_committed_value(case, "notes", list(notes))  # no lazy load of every note
    out = CaseOut.model_validate(case)
    out.notes_total = total
    return out


@router.get("/api/cases", response_model=PaginatedResponse)
async def list_cases(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    status: str | None = None, severity: str | None = None,
    hostname: str | None = None, search: str | None = None,
    start_time: datetime | None = None, end_time: datetime | None = None,
    alert_id: UUID | None = None,
    summary: bool = False,
):
    q = select(Case)
    if group_filter:
        q = q.where(Case.group_id == group_filter)
    if alert_id:
        q = q.where(or_(Case.alert_id == alert_id, Case.id.in_(
            select(CaseAlert.case_id).where(CaseAlert.alert_id == alert_id, CaseAlert.status == "linked"))))
    if status:
        q = q.where(Case.status == status)
    if severity:
        q = q.where(Case.severity == severity)
    if hostname:
        matching_alerts = select(Alert.id).where(Alert.hostname.ilike(f"%{hostname}%"))
        q = q.where(or_(Case.alert_id.in_(matching_alerts), Case.id.in_(
            select(CaseAlert.case_id).where(CaseAlert.alert_id.in_(matching_alerts), CaseAlert.status == "linked"))))
    if search:
        q = q.where(or_(Case.title.ilike(f"%{search}%"), Case.description.ilike(f"%{search}%")))
    if start_time:
        q = q.where(Case.created_at >= start_time)
    if end_time:
        q = q.where(Case.created_at <= end_time)
    total = (await db.execute(q.with_only_columns(func.count(), maintain_column_froms=True))).scalar_one()
    q = q.order_by(Case.updated_at.desc(), Case.id.desc())
    if summary:
        # Bound previews in SQL so large investigation bodies never leave the DB.
        # alert_count is a correlated column — linked case_alerts UNION the primary
        # alert, deduplicated — so the summary stays exactly two statements.
        linked_count = select(func.count()).select_from(
            select(CaseAlert.alert_id).where(
                CaseAlert.case_id == Case.id, CaseAlert.status == "linked",
            ).union(
                select(Case.alert_id).where(Case.alert_id.is_not(None))
            ).subquery()
        ).correlate(Case).scalar_subquery()
        q = q.with_only_columns(*(
            linked_count.label("alert_count") if name == "alert_count" else
            func.substr(getattr(Case, name), 1, 500).label(name)
            if name in {"description", "ai_reasoning"} else getattr(Case, name)
            for name in CaseSummaryOut.model_fields
        ))
        result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
        items = [CaseSummaryOut.model_validate(row) for row in result.mappings()]
    else:
        q = q.options(selectinload(Case.notes))
        result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
        cases = result.scalars().all()
        links = (await db.execute(select(CaseAlert.case_id, CaseAlert.alert_id).where(
            CaseAlert.case_id.in_([c.id for c in cases]), CaseAlert.status == "linked",
        ))).all()
        counts: dict = {}
        for cid, aid in links:
            counts.setdefault(cid, set()).add(aid)
        items = []
        for c in cases:
            linked = set(counts.get(c.id, ()))
            if c.alert_id:
                linked.add(c.alert_id)
            items.append(CaseOut.model_validate(c).model_copy(update={"alert_count": len(linked)}))
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=items)

@router.post("/api/cases", response_model=CaseOut, status_code=201)
async def create_case(
    body: CaseCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    alert = None
    if body.alert_id:
        # The alert must be visible to the caller; the case lives in the alert's
        # group so that group's analysts see it (matters for superadmins).
        alert = await fetch_scoped(db, Alert, body.alert_id, group_filter, detail="Alert not found")
    case = Case(**body.model_dump(), group_id=alert.group_id if alert else current_user.group_id)
    if alert:
        ioc = {"source_ip": alert.source_ip, "mitre_techniques": list(alert.mitre_techniques or [])}
        if alert.hostname:
            ioc["hostname"] = alert.hostname
            ioc["affected_hosts"] = [alert.hostname]
        case.ioc_data = {k: v for k, v in ioc.items() if v}
    db.add(case)
    await db.flush()
    await enqueue_case_event(db, CaseEvent(case.id, case.group_id, "case.created", case.alert_id))
    if alert:
        db.add(CaseNote(
            case_id=case.id, author_id=current_user.id, is_ai_generated=False,
            content=(f"Case created manually by **{current_user.username}** from alert "
                     f"[{alert.title}](/alerts/{alert.id}) ({alert.severity}"
                     + (f", host {alert.hostname}" if alert.hostname else "") + ")."),
        ))
    await db.commit()
    case = await fetch_scoped(db, Case, case.id, None, detail="Case not found")
    background.add_task(audit_log, db, current_user.id, "case_created", "case", str(case.id))
    return await _case_out(db, case)

@router.get("/api/cases/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if not case or (group_filter and case.group_id != group_filter):
        raise HTTPException(status_code=404, detail="Case not found")
    return await _case_out(db, case)


@router.get("/api/cases/{case_id}/notes", response_model=list[CaseNoteOut])
async def list_case_notes(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(CASE_NOTES_LIMIT, ge=1, le=500),
):
    """Notes newest first, a page at a time."""
    await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    notes = (await db.execute(
        select(CaseNote).where(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.desc(), CaseNote.id.desc()).offset(offset).limit(limit)
    )).scalars().all()
    return [CaseNoteOut.model_validate(n) for n in notes]

@router.put("/api/cases/{case_id}", response_model=CaseOut)
async def update_case(
    case_id: UUID, body: CaseUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(case, field, value)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user.id, "case_updated", "case", str(case_id))
    if body.status in ("resolved", "closed"):
        background.add_task(_push_rag_reindex, str(case_id))
    return await _case_out(db, case)

@router.post("/api/cases/{case_id}/escalate", response_model=CaseOut)
async def escalate_case(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    from datetime import datetime
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    case.status = "escalated"
    case.escalated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user.id, "case_escalated", "case", str(case_id))
    return await _case_out(db, case)

@router.post("/api/cases/{case_id}/notes", response_model=CaseNoteOut, status_code=201)
async def add_note(
    case_id: UUID, body: CaseNoteCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    note = CaseNote(case_id=case_id, author_id=current_user.id, content=body.content, is_ai_generated=False)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return CaseNoteOut.model_validate(note)

@router.get("/api/cases/{case_id}/feedback", response_model=list[AiFeedbackOut])
async def list_case_feedback(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    result = await db.execute(
        select(AiFeedback)
        .where(AiFeedback.entity_type == "case", AiFeedback.entity_id == case_id)
        .order_by(AiFeedback.created_at.desc())
    )
    return [AiFeedbackOut.model_validate(f) for f in result.scalars().all()]

@router.post("/api/cases/{case_id}/feedback", response_model=AiFeedbackOut, status_code=201)
async def submit_case_feedback(
    case_id: UUID, body: AiFeedbackCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")

    feedback = AiFeedback(
        entity_type="case",
        entity_id=case_id,
        context_text=f"{case.title}\n{case.description or ''}".strip(),
        ai_verdict=case.ioc_data.get("verdict") if case.ioc_data else None,
        rating=body.rating,
        correct_verdict=body.correct_verdict,
        note=body.note,
        group_id=case.group_id,
        created_by=current_user.id,
    )
    db.add(feedback)
    await db.commit()
    await db.refresh(feedback)
    background.add_task(_push_feedback_reindex, str(feedback.id))
    return AiFeedbackOut.model_validate(feedback)

@router.delete("/api/cases/{case_id}", status_code=204)
async def delete_case(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    await db.delete(case)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "case_deleted", "case", str(case_id))

@router.get("/api/cases/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: User = Depends(get_current_user),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """Return explicitly linked alert evidence in chronological order."""
    import uuid as _uuid

    case = await fetch_scoped(db, Case, _uuid.UUID(case_id), group_filter, detail="Case not found")

    items = []
    linked_ids = set((await db.execute(select(CaseAlert.alert_id).where(
        CaseAlert.case_id == case.id, CaseAlert.status == "linked",
    ))).scalars().all())
    if case.alert_id:
        linked_ids.add(case.alert_id)
    related_alerts = (await db.execute(select(Alert).where(
        Alert.id.in_(linked_ids), Alert.group_id == case.group_id,
    ).order_by(Alert.created_at.asc()))).scalars().all()
    for a in related_alerts:
        items.append({
            "type": "alert", "id": str(a.id), "ts": a.created_at.isoformat(),
            "title": a.title, "severity": a.severity, "source_ip": a.source_ip,
            "hostname": a.hostname, "is_this_case": True,
            "mitre_techniques": a.mitre_techniques or [], "kill_chain_stage": a.kill_chain_stage,
        })

    # Alert notes follow the same explicitly linked, group-scoped evidence.
    if related_alerts:
        notes = (await db.execute(
            select(AlertNote)
            .where(AlertNote.alert_id.in_([a.id for a in related_alerts]))
            .order_by(AlertNote.created_at.asc())
        )).scalars().all()
        for n in notes:
            content_preview = n.content[:120] + ("…" if len(n.content) > 120 else "")
            items.append({
                "type": "note",
                "id": str(n.id),
                "ts": n.created_at.isoformat(),
                "title": content_preview,
            })

    items.sort(key=lambda x: x["ts"])
    return {"case_id": case_id, "items": items}
