"""Incident reports (services/incident_report.py): written from a case, edited
as a draft, finalized by an admin into a numbered PDF whose SHA-256 is kept so
anyone can later check a copy is the real one."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.llm_client import generate_text
from app.models.models import Case, IncidentReport, PlatformSetting, User
from app.services import incident_report as svc
from app.services.audit import audit_log

router = APIRouter(tags=["incident-reports"])
Read = require_permission("alerts:read")
Write = require_permission("cases:manage")
NUMBER_LOCK = 7438002

Lang = Literal["id", "en"]
Classification = Literal["public", "internal", "confidential", "restricted"]
Priority = Literal["low", "normal", "high", "urgent"]


class CreateIn(BaseModel):
    language: Lang = "id"
    use_ai: bool = True
    classification: Classification = "confidential"
    audience: Optional[str] = Field(None, max_length=300)


class Row(BaseModel):
    time: Optional[str] = Field(None, max_length=40)
    text: str = Field(max_length=2000)
    by: Optional[str] = Field(None, max_length=255)
    source: Optional[str] = Field(None, max_length=30)


class Ioc(BaseModel):
    type: str = Field(max_length=40)
    value: str = Field(max_length=300)
    note: str = Field("", max_length=200)


class UpdateIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    language: Lang = "id"
    classification: Classification = "confidential"
    priority: Priority = "normal"
    audience: Optional[str] = Field(None, max_length=300)
    sections: dict[str, str] = Field(default_factory=dict)
    timeline: list[Row] = Field(default_factory=list, max_length=500)
    actions: list[Row] = Field(default_factory=list, max_length=500)
    iocs: list[Ioc] = Field(default_factory=list, max_length=200)


class VerifyIn(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


def _out(r: IncidentReport, *, full: bool = True) -> dict:
    out = {
        "id": str(r.id), "case_id": str(r.case_id) if r.case_id else None, "number": r.number,
        "status": r.status, "language": r.language, "title": r.title, "classification": r.classification,
        "priority": r.priority, "audience": r.audience, "ai_used": r.ai_used,
        "created_by_name": r.created_by_name, "finalized_by_name": r.finalized_by_name,
        "finalized_at": r.finalized_at.isoformat() if r.finalized_at else None,
        "pdf_sha256": r.pdf_sha256, "content_sha256": r.content_sha256,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }
    if full:
        out["content"] = r.content
    return out


async def _setting(db, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return row.value if row and row.value else default


async def _case(db, case_id: UUID, group_filter: str | None) -> Case:
    case = await db.get(Case, case_id)
    if case is None or (group_filter is not None and case.group_id != group_filter):
        raise HTTPException(404, "Case not found")
    return case


async def _report(db, report_id: UUID, group_filter: str | None) -> IncidentReport:
    r = await db.get(IncidentReport, report_id)
    if r is None or (group_filter is not None and r.group_id != group_filter):
        raise HTTPException(404, "Report not found")
    return r


def _draft_only(r: IncidentReport) -> None:
    if r.status != "draft":
        raise HTTPException(409, "This report is final and can no longer be changed")


async def _compose(db, case: Case, language: str, use_ai: bool) -> tuple[dict, bool]:
    content = await svc.build_content(db, case)
    if not use_ai:
        return content, False
    api_key = await _setting(db, "ninerouter_api_key")
    model = await _setting(db, "ninerouter_model", "combo")

    async def generate(prompt: str) -> str:
        return await generate_text(api_key, model, prompt, max_tokens=3000, db=db)
    prose = await svc.narrate(content, language, generate)
    if prose:
        content["sections"].update(prose)
    return content, bool(prose)


@router.post("/api/cases/{case_id}/incident-reports", status_code=201)
async def create_report(
    case_id: UUID,
    body: CreateIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Write)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    case = await _case(db, case_id, group_filter)
    content, ai_used = await _compose(db, case, body.language, body.use_ai)
    r = IncidentReport(case_id=case.id, group_id=case.group_id, language=body.language, title=case.title[:300],
                       classification=body.classification, priority=svc.priority_for(case.severity),
                       audience=body.audience, content=content, ai_used=ai_used, created_by=user.id,
                       created_by_name=user.username)
    db.add(r)
    await db.commit()
    await db.refresh(r)
    await audit_log(db, user.id, "incident_report_created", "incident_report", str(r.id),
                    {"case_id": str(case.id), "ai": ai_used})
    return _out(r)


@router.get("/api/incident-reports")
async def list_reports(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    status: Optional[Literal["draft", "final"]] = None,
    case_id: Optional[UUID] = None,
    q: Optional[str] = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
):
    stmt = select(IncidentReport)
    if group_filter is not None:
        stmt = stmt.where(IncidentReport.group_id == group_filter)
    if status:
        stmt = stmt.where(IncidentReport.status == status)
    if case_id:
        stmt = stmt.where(IncidentReport.case_id == case_id)
    if q:
        stmt = stmt.where(or_(IncidentReport.title.ilike(f"%{q}%"), IncidentReport.number.ilike(f"%{q}%")))
    rows = (await db.execute(stmt.order_by(IncidentReport.created_at.desc()).limit(limit))).scalars().all()
    return [_out(r, full=False) for r in rows]


@router.get("/api/incident-reports/{report_id}")
async def get_report(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    return _out(await _report(db, report_id, group_filter))


@router.put("/api/incident-reports/{report_id}")
async def update_report(
    report_id: UUID,
    body: UpdateIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Write)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    r = await _report(db, report_id, group_filter)
    _draft_only(r)
    content = dict(r.content or {})
    content["sections"] = {k: (body.sections.get(k) or "")[:8000] for k in svc.SECTIONS}
    content["timeline"] = [x.model_dump() for x in body.timeline]
    content["actions"] = [x.model_dump() for x in body.actions]
    content["iocs"] = [x.model_dump() for x in body.iocs]
    r.title, r.language, r.classification = body.title.strip(), body.language, body.classification
    r.priority, r.audience, r.content = body.priority, body.audience, content
    await db.commit()
    await db.refresh(r)
    return _out(r)


@router.post("/api/incident-reports/{report_id}/regenerate")
async def regenerate_report(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Write)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    use_ai: bool = True,
):
    """Rebuild a draft from the case as it is now (new alerts, a finished investigation)."""
    r = await _report(db, report_id, group_filter)
    _draft_only(r)
    if r.case_id is None:
        raise HTTPException(409, "The case of this report was deleted")
    case = await _case(db, r.case_id, group_filter)
    r.content, r.ai_used = await _compose(db, case, r.language, use_ai)
    await db.commit()
    await db.refresh(r)
    return _out(r)


@router.post("/api/incident-reports/{report_id}/finalize")
async def finalize_report(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Write)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """Admins only: number the report, render its PDF once and lock it."""
    if user.role.name not in ("admin", "superadmin"):
        raise HTTPException(403, "Only an admin can finalize a report")
    r = await _report(db, report_id, group_filter)
    _draft_only(r)
    now = datetime.now(timezone.utc)
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": NUMBER_LOCK})
    prefix = f"IR-{now.year}-"
    last = (await db.execute(select(IncidentReport.number).where(IncidentReport.number.like(f"{prefix}%"))
                             .order_by(IncidentReport.number.desc()).limit(1))).scalar_one_or_none()
    seq = int(last.rsplit("-", 1)[1]) + 1 if last else 1
    r.number = f"{prefix}{seq:04d}"
    r.status = "final"
    r.finalized_by, r.finalized_by_name, r.finalized_at = user.id, user.username, now
    r.content_sha256 = svc.content_hash(r)
    r.pdf = svc.render_pdf(r, await _setting(db, "org_name", ""), draft=False)
    r.pdf_sha256 = hashlib.sha256(r.pdf).hexdigest()
    await db.commit()
    await db.refresh(r)
    await audit_log(db, user.id, "incident_report_finalized", "incident_report", str(r.id),
                    {"number": r.number, "pdf_sha256": r.pdf_sha256})
    return _out(r)


@router.get("/api/incident-reports/{report_id}/pdf")
async def report_pdf(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    r = await _report(db, report_id, group_filter)
    if r.status == "final" and r.pdf:
        pdf = r.pdf
        await audit_log(db, user.id, "incident_report_downloaded", "incident_report", str(r.id), {"number": r.number})
    else:
        pdf = svc.render_pdf(r, await _setting(db, "org_name", ""), draft=True)
    name = (r.number or f"DRAFT-{str(r.id)[:8]}") + ".pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/api/incident-reports/verify")
async def verify_report(
    body: VerifyIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Read)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """The browser hashes the PDF; only the hash is sent."""
    stmt = select(IncidentReport).where(IncidentReport.pdf_sha256 == body.sha256.lower(),
                                        IncidentReport.status == "final")
    if group_filter is not None:
        stmt = stmt.where(IncidentReport.group_id == group_filter)
    r = (await db.execute(stmt)).scalar_one_or_none()
    if r is None:
        return {"match": False}
    return {"match": True, "number": r.number, "title": r.title, "finalized_by_name": r.finalized_by_name,
            "finalized_at": r.finalized_at.isoformat() if r.finalized_at else None, "id": str(r.id)}


@router.delete("/api/incident-reports/{report_id}", status_code=204)
async def delete_report(
    report_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(Write)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
):
    """Drafts only; a final report stays."""
    r = await _report(db, report_id, group_filter)
    _draft_only(r)
    await db.delete(r)
    await db.commit()
    await audit_log(db, user.id, "incident_report_draft_deleted", "incident_report", str(report_id))
