# server-api/app/api/routes/investigations.py
"""AI case investigations (services/investigator.py): start one from a case, follow its steps, cancel it."""
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import Case, CaseInvestigation, User
from app.services import investigator
from app.services.audit import audit_log

router = APIRouter(tags=["investigations"])


class InvestigationOut(BaseModel):
    id: UUID
    case_id: UUID
    status: str
    model: str | None = None
    verdict: str | None = None
    report: str | None = None
    error: str | None = None
    steps: list[dict[str, Any]] = []
    created_at: datetime
    finished_at: datetime | None = None
    model_config = {"from_attributes": True}


def _can_run_live_response(user: User) -> bool:
    return user.role.name == "superadmin" or "agents:manage" in {p.name for p in user.role.permissions}


@router.post("/api/cases/{case_id}/investigations", response_model=InvestigationOut, status_code=202)
async def start_investigation(
    case_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    # the AI runs live response on the case's hosts in this analyst's name
    if not _can_run_live_response(user):
        raise HTTPException(403, "Starting an AI investigation needs the agents:manage permission (live response)")
    case = await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    busy = (await db.execute(select(CaseInvestigation.id).where(
        CaseInvestigation.case_id == case.id, CaseInvestigation.status.in_(("queued", "running"))
    ))).first()
    if busy:
        raise HTTPException(409, "An investigation of this case is already running")
    from app.services.assistant import _graph_config
    api_key, model, _ = await _graph_config(db, case.group_id)
    if not api_key:
        raise HTTPException(422, "No AI provider configured (Settings → AI: 9router API key)")

    inv = CaseInvestigation(case_id=case.id, group_id=case.group_id, started_by=user.id, model=model,
                            status="queued", steps=[])
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    investigator.spawn(inv.id)
    background.add_task(audit_log, db, user.id, "ai_investigation_started", "case", str(case.id),
                        {"investigation": str(inv.id)})
    return inv


@router.get("/api/cases/{case_id}/investigations", response_model=list[InvestigationOut])
async def list_investigations(
    case_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    await fetch_scoped(db, Case, case_id, group_filter, detail="Case not found")
    rows = (await db.execute(
        select(CaseInvestigation).where(CaseInvestigation.case_id == case_id)
        .order_by(desc(CaseInvestigation.created_at)).limit(20)
    )).scalars().all()
    return rows


async def _get(db, inv_id: UUID, group_filter: str | None) -> CaseInvestigation:
    inv = await db.get(CaseInvestigation, inv_id)
    if inv is None or (group_filter is not None and inv.group_id != group_filter):
        raise HTTPException(404, "Investigation not found")
    return inv


@router.get("/api/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(
    inv_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    return await _get(db, inv_id, group_filter)


@router.post("/api/investigations/{inv_id}/cancel", response_model=InvestigationOut)
async def cancel_investigation(
    inv_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("cases:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    inv = await _get(db, inv_id, group_filter)
    if inv.status in ("queued", "running"):
        inv.cancel_requested = True  # the run stops at its next step (flows in flight finish on their own)
        await db.commit()
        await db.refresh(inv)
        background.add_task(audit_log, db, user.id, "ai_investigation_cancelled", "case", str(inv.case_id),
                            {"investigation": str(inv.id)})
    return inv
