# server-api/app/api/routes/cases.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.deps import get_current_user, require_permission, get_scoped_group
from app.models.models import (
    AiFeedback, Alert, AlertNote, Case, CaseNote, FimEvent, IocLink,
    IocObservation, SoarRun, SoarRunStep, User,
)
from app.schemas.schemas import (
    AiFeedbackCreate, AiFeedbackOut, CaseOut, CaseCreate, CaseUpdate,
    CaseNoteCreate, CaseNoteOut, PaginatedResponse,
)
from app.services.audit import audit_log
from app.services.custody_export import SIGNATURE_ALGORITHM, build_export_bundle, sign_bundle
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

async def _push_feedback_reindex(feedback_id: str) -> None:
    """Push feedback_id to Redis queue so the worker embeds it for RAG retrieval."""
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush("siem:rag:feedback-reindex", feedback_id)
        await redis.aclose()
    except Exception:
        pass  # non-critical: feedback row is already saved regardless

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
    status: str | None = None, severity: str | None = None,
    hostname: str | None = None, search: str | None = None,
    start_time: datetime | None = None, end_time: datetime | None = None,
):
    from sqlalchemy import func
    q = _case_q(group_filter)
    if status:
        q = q.where(Case.status == status)
    if severity:
        q = q.where(Case.severity == severity)
    if hostname:
        q = q.where(Case.alert_id.in_(
            select(Alert.id).where(Alert.hostname.ilike(f"%{hostname}%"))
        ))
    if search:
        q = q.where(or_(Case.title.ilike(f"%{search}%"), Case.description.ilike(f"%{search}%")))
    if start_time:
        q = q.where(Case.created_at >= start_time)
    if end_time:
        q = q.where(Case.created_at <= end_time)
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
    background.add_task(audit_log, db, current_user, "case_created", "case", str(case.id))
    return CaseOut.model_validate(case)

@router.get("/api/cases/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Case).options(selectinload(Case.notes)).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    result = await db.execute(query)
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Case).options(selectinload(Case.notes)).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    result = await db.execute(query)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(case, field, value)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user, "case_updated", "case", str(case_id))
    if body.status in ("resolved", "closed"):
        background.add_task(_push_rag_reindex, str(case_id))
    return CaseOut.model_validate(case)

@router.post("/api/cases/{case_id}/escalate", response_model=CaseOut)
async def escalate_case(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    from datetime import datetime
    query = select(Case).options(selectinload(Case.notes)).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    result = await db.execute(query)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.status = "escalated"
    case.escalated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)
    background.add_task(audit_log, db, current_user, "case_escalated", "case", str(case_id))
    return CaseOut.model_validate(case)

@router.post("/api/cases/{case_id}/notes", response_model=CaseNoteOut, status_code=201)
async def add_note(
    case_id: UUID, body: CaseNoteCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Case.id).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    result = await db.execute(query)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Case not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    case_query = select(Case.id).where(Case.id == case_id)
    if group_filter is not None:
        case_query = case_query.where(Case.group_id == group_filter)
    if (await db.execute(case_query)).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Case not found")
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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Case).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    case = (await db.execute(query)).scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

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
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    query = select(Case).where(Case.id == case_id)
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    result = await db.execute(query)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    await db.delete(case)
    await db.commit()
    background.add_task(audit_log, db, current_user, "case_deleted", "case", str(case_id))

def _encode_timeline_cursor(offset: int) -> str:
    import base64
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_timeline_cursor(cursor: str | None) -> int:
    import base64
    if not cursor:
        return 0
    try:
        offset = int(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        raise HTTPException(status_code=422, detail="invalid cursor")
    if offset < 0:
        raise HTTPException(status_code=422, detail="invalid cursor")
    return offset


async def _load_case_for_timeline(db: AsyncSession, case_id: str, group_filter: str | None) -> Case:
    import uuid as _uuid
    query = select(Case).where(Case.id == _uuid.UUID(case_id))
    if group_filter is not None:
        query = query.where(Case.group_id == group_filter)
    case = (await db.execute(query)).scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


async def _build_case_timeline_items(db: AsyncSession, case: Case) -> list[dict]:
    """Assemble the full, unpaginated, chronologically-sorted timeline for a
    case: nearby alerts, case/alert notes, FIM events, TI/IOC enrichment, and
    SOAR execution steps, all within a ±24h window around case creation.
    Shared by the paginated `/timeline` route and the chain-of-custody export."""
    from datetime import timedelta

    items = []
    window_start = case.created_at - timedelta(hours=24)
    window_end   = case.created_at + timedelta(hours=24)

    # Resolve source_ip/hostname from the triggering alert if available
    source_ip = None
    hostname  = None
    triggering = None
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
                "mitre_techniques": a.mitre_techniques or [],
                "kill_chain_stage": a.kill_chain_stage,
                "correlation_id": a.correlation_id,
                "correlation_key": a.correlation_key,
                "source_event_ids": a.source_event_ids or [],
            })

            if a.correlation_key and a.source_event_ids:
                items.append({
                    "type": "detection_provenance",
                    "id": f"provenance:{a.id}",
                    "ts": a.created_at.isoformat(),
                    "title": "Correlated detection provenance",
                    "correlation_id": a.correlation_id,
                    "correlation_key": a.correlation_key,
                    "source_event_ids": a.source_event_ids,
                })

    # Notes on the triggering alert
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
                "note_source": "alert",
            })

    # Notes on the case itself
    case_notes = (await db.execute(
        select(CaseNote)
        .where(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.asc())
    )).scalars().all()
    for n in case_notes:
        content_preview = n.content[:120] + ("…" if len(n.content) > 120 else "")
        items.append({
            "type": "note",
            "id": str(n.id),
            "ts": n.created_at.isoformat(),
            "title": content_preview,
            "note_source": "case",
            "is_ai_generated": n.is_ai_generated,
        })

    # FIM events on the triggering alert's agent, within the same window
    if case.alert_id and getattr(triggering, "agent_id", None):
        fim_events = (await db.execute(
            select(FimEvent)
            .where(
                FimEvent.agent_id == triggering.agent_id,
                FimEvent.detected_at.between(window_start, window_end),
            )
            .order_by(FimEvent.detected_at.asc())
            .limit(50)
        )).scalars().all()
        for f in fim_events:
            items.append({
                "type": "fim",
                "id": str(f.id),
                "ts": f.detected_at.isoformat(),
                "title": f"{f.event_type}: {f.path}",
                "path": f.path,
                "event_type": f.event_type,
                "sha256": f.sha256,
            })

    # Threat-intel enrichment linked to the triggering alert
    if case.alert_id:
        ioc_rows = (await db.execute(
            select(IocLink, IocObservation)
            .join(IocObservation, IocObservation.id == IocLink.ioc_id)
            .where(IocLink.entity_type == "alert", IocLink.entity_id == str(case.alert_id))
            .order_by(IocLink.linked_at.asc())
        )).all()
        for link, obs in ioc_rows:
            items.append({
                "type": "enrichment",
                "id": str(link.id),
                "ts": link.linked_at.isoformat(),
                "title": f"IOC {obs.verdict}: {obs.indicator} ({obs.ioc_type})",
                "indicator": obs.indicator,
                "ioc_type": obs.ioc_type,
                "verdict": obs.verdict,
                "confidence": obs.confidence,
                "source": obs.source,
            })

    # SOAR execution steps for any run triggered by this alert
    if case.alert_id:
        soar_rows = (await db.execute(
            select(SoarRunStep)
            .join(SoarRun, SoarRun.id == SoarRunStep.run_id)
            .where(SoarRun.trigger_ref["alert_id"].astext == str(case.alert_id))
            .order_by(SoarRunStep.acted_at.asc())
        )).scalars().all()
        for step in soar_rows:
            items.append({
                "type": "soar_step",
                "id": str(step.id),
                "ts": (step.acted_at or case.created_at).isoformat(),
                "title": f"SOAR {step.action_type}: {step.status}",
                "action_type": step.action_type,
                "status": step.status,
                "is_destructive": step.is_destructive,
                "is_reversible": step.is_reversible,
            })

    items.sort(key=lambda x: x["ts"])
    return items


@router.get("/api/cases/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    _: User = Depends(get_current_user),
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    cursor: str | None = None,
    limit: int = 100,
):
    """Unified chronological timeline for a case: nearby alerts, case/alert
    notes, FIM events, TI/IOC enrichment, and SOAR execution steps, all
    within a ±24h window around case creation. Cursor-paginated: pass the
    response's `next_cursor` back to get the next page; `next_cursor` is
    `null` once every item has been returned."""
    limit = max(1, min(limit, 500))
    case = await _load_case_for_timeline(db, case_id, group_filter)
    items = await _build_case_timeline_items(db, case)

    offset = _decode_timeline_cursor(cursor)
    page = items[offset:offset + limit]
    next_cursor = _encode_timeline_cursor(offset + limit) if offset + limit < len(items) else None
    return {"case_id": case_id, "items": page, "next_cursor": next_cursor, "total": len(items)}


def _case_export_out(case: Case) -> dict:
    return {
        "id": str(case.id),
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "alert_id": str(case.alert_id) if case.alert_id else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "group_id": case.group_id,
    }


def _alert_export_out(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "title": a.title,
        "severity": a.severity,
        "status": a.status,
        "source_ip": a.source_ip,
        "hostname": a.hostname,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "mitre_techniques": a.mitre_techniques or [],
        "correlation_id": a.correlation_id,
        "source_event_ids": a.source_event_ids or [],
    }


@router.get("/api/cases/{case_id}/export")
async def export_case(
    case_id: str,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """Signed chain-of-custody export: the case, its full unified timeline,
    and every alert referenced in that timeline, bundled with a per-section
    SHA-256 artifact hash and an overall HMAC-SHA256 signature, so a
    recipient can later prove (via `POST /api/exports/verify`) that the
    export was not altered after it left the platform."""
    import uuid as _uuid

    case = await _load_case_for_timeline(db, case_id, group_filter)
    items = await _build_case_timeline_items(db, case)

    alert_ids = {item["id"] for item in items if item["type"] == "alert"}
    alerts = []
    if alert_ids:
        rows = (
            await db.execute(select(Alert).where(Alert.id.in_([_uuid.UUID(a) for a in alert_ids])))
        ).scalars().all()
        alerts = [_alert_export_out(a) for a in rows]

    exported_at = datetime.now(timezone.utc).isoformat()
    bundle = build_export_bundle(
        case=_case_export_out(case),
        timeline_items=items,
        alerts=alerts,
        exported_by=str(current_user.id),
        exported_at=exported_at,
    )
    signature = sign_bundle(bundle)
    background.add_task(
        audit_log, db, current_user, "case_exported", "case", str(case.id),
        {"item_count": len(items), "alert_count": len(alerts)},
    )
    return {"export": bundle, "signature": signature, "algorithm": SIGNATURE_ALGORITHM}
