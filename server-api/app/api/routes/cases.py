# server-api/app/api/routes/cases.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timezone
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group
from app.models.models import Alert, AlertNote, Case, CaseNote, User
from app.schemas.schemas import CaseOut, CaseCreate, CaseUpdate, CaseNoteCreate, CaseNoteOut, PaginatedResponse
from app.services.audit import audit_log
from app.core.config import settings
import redis.asyncio as aioredis

router = APIRouter(tags=["cases"])

async def _push_rag_reindex(case_id: str) -> None:
    """Push case_id to Redis reindex queue so worker indexes it immediately."""
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush("siem:rag:reindex", case_id)
        await redis.aclose()
    except Exception:
        pass  # non-critical: hourly loop will catch it

def _case_q(group_filter):
    q = select(Case).options(selectinload(Case.notes))
    if group_filter:
        q = q.where(Case.group_id == group_filter)
    return q

@router.get("/api/cases", response_model=PaginatedResponse)
async def list_cases(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    page: int = 1, page_size: int = 25,
    status: str | None = None,
):
    from sqlalchemy import func
    q = _case_q(group_filter)
    if status:
        q = q.where(Case.status == status)
    q = q.order_by(Case.created_at.desc())
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    cases = result.scalars().all()
    return PaginatedResponse(total=total, page=page, page_size=page_size,
                             items=[CaseOut.model_validate(c) for c in cases])

@router.post("/api/cases", response_model=CaseOut, status_code=201)
async def create_case(
    body: CaseCreate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    case = Case(**body.model_dump(), group_id=current_user.group_id)
    db.add(case)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user.id, "case_created", "case", str(case.id))
    return CaseOut.model_validate(case)

@router.get("/api/cases/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Case).options(selectinload(Case.notes)).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return CaseOut.model_validate(case)

@router.put("/api/cases/{case_id}", response_model=CaseOut)
async def update_case(
    case_id: UUID, body: CaseUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    result = await db.execute(select(Case).options(selectinload(Case.notes)).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(case, field, value)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user.id, "case_updated", "case", str(case_id))
    if body.status in ("resolved", "closed"):
        background.add_task(_push_rag_reindex, str(case_id))
    return CaseOut.model_validate(case)

@router.post("/api/cases/{case_id}/escalate", response_model=CaseOut)
async def escalate_case(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    from datetime import datetime
    result = await db.execute(select(Case).options(selectinload(Case.notes)).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.status = "escalated"
    case.escalated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user.id, "case_escalated", "case", str(case_id))
    return CaseOut.model_validate(case)

@router.post("/api/cases/{case_id}/notes", response_model=CaseNoteOut, status_code=201)
async def add_note(
    case_id: UUID, body: CaseNoteCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Case not found")
    note = CaseNote(case_id=case_id, author_id=current_user.id, content=body.content, is_ai_generated=False)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return CaseNoteOut.model_validate(note)

@router.delete("/api/cases/{case_id}", status_code=204)
async def delete_case(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    await db.delete(case)
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "case_deleted", "case", str(case_id))

@router.get("/api/cases/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    _: User = Depends(get_current_user),
):
    """Return chronological related alerts and notes for a case (±24h window around case creation)."""
    import uuid as _uuid
    from datetime import timedelta

    case = await db.get(Case, _uuid.UUID(case_id))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    items = []
    window_start = case.created_at - timedelta(hours=24)
    window_end   = case.created_at + timedelta(hours=24)

    # Resolve source_ip/hostname from the triggering alert if available
    source_ip = None
    hostname  = None
    if case.alert_id:
        triggering = await db.get(Alert, case.alert_id)
        if triggering:
            source_ip = triggering.source_ip
            hostname  = triggering.hostname

    # Related alerts: same source_ip or hostname within ±24h
    if source_ip or hostname:
        filters = [Alert.created_at.between(window_start, window_end)]
        if source_ip and hostname:
            filters.append(or_(Alert.source_ip == source_ip, Alert.hostname == hostname))
        elif source_ip:
            filters.append(Alert.source_ip == source_ip)
        else:
            filters.append(Alert.hostname == hostname)

        related_alerts = (await db.execute(
            select(Alert).where(*filters).order_by(Alert.created_at.asc()).limit(50)
        )).scalars().all()

        for a in related_alerts:
            items.append({
                "type": "alert",
                "id": str(a.id),
                "ts": a.created_at.isoformat(),
                "title": a.title,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
                "is_this_case": bool(case.alert_id and str(a.id) == str(case.alert_id)),
            })

    # Case notes linked to the triggering alert
    if case.alert_id:
        notes = (await db.execute(
            select(AlertNote)
            .where(AlertNote.alert_id == case.alert_id)
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
