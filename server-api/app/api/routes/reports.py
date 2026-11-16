# server-api/app/api/routes/reports.py
"""Period summary (services/periodic_report.py): preview the numbers on the
page, generate the PDF with an AI executive summary, and keep every generated
PDF so it can be downloaded again."""
import hashlib
from datetime import date
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.llm_client import generate_text
from app.models.models import PlatformSetting, ReportRun, User
from app.schemas.schemas import ReportGenerateRequest
from app.services import periodic_report as svc
from app.services.audit import audit_log

router = APIRouter(prefix="/api/reports", tags=["reports"])
Perm = require_permission("alerts:read")
MAX_DAYS = 400


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return (row.value if row and row.value else default)


def _check_range(date_from: date, date_to: date) -> None:
    if date_from > date_to:
        raise HTTPException(422, "The start date must be on or before the end date")
    if (date_to - date_from).days > MAX_DAYS:
        raise HTTPException(422, f"A report covers at most {MAX_DAYS} days")


@router.get("/summary")
async def report_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    date_from: date = Query(...),
    date_to: date = Query(...),
    tz: Optional[str] = Query(None, max_length=64),
):
    """The numbers of the period, for the page; no AI, nothing stored."""
    _check_range(date_from, date_to)
    zone = svc.zone(tz)
    start, end = svc.window(date_from, date_to, zone)
    return await svc.gather(db, group_filter, start, end, zone)


@router.post("/generate")
async def generate_report(
    body: ReportGenerateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    user: Annotated[User, Depends(Perm)],
):
    _check_range(body.date_from, body.date_to)
    zone = svc.zone(body.tz)
    lang = svc.lang_code(body.language)
    start, end = svc.window(body.date_from, body.date_to, zone)
    stats = await svc.gather(db, group_filter, start, end, zone)

    narrative = ""
    if body.use_ai:
        api_key = await _get_setting(db, "ninerouter_api_key", "")
        model = await _get_setting(db, "ninerouter_model", "combo")
        narrative = (await generate_text(api_key, model, svc.narration_prompt(stats, lang), max_tokens=2000, db=db) or "").strip()

    org_name = await _get_setting(db, "org_name", "")
    pdf = svc.render_pdf(stats, narrative, org_name, lang, user.username, zone)
    run = ReportRun(group_id=group_filter, period_from=start, period_to=end, language=lang, stats=stats,
                    narrative=narrative or None, pdf=pdf, pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                    created_by=user.id, created_by_name=user.username)
    db.add(run)
    await db.commit()
    await audit_log(db, user.id, "periodic_report_generated", "report_run", str(run.id),
                    {"from": body.date_from.isoformat(), "to": body.date_to.isoformat(), "ai": bool(narrative)})

    filename = f"security-report-{body.date_from.isoformat()}-to-{body.date_to.isoformat()}.pdf"
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{filename}"', "X-Report-Id": str(run.id)})


@router.get("/history")
async def report_history(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
    limit: int = Query(50, ge=1, le=200),
):
    q = select(ReportRun.id, ReportRun.period_from, ReportRun.period_to, ReportRun.language, ReportRun.narrative,
               ReportRun.created_by_name, ReportRun.created_at, ReportRun.pdf_sha256, ReportRun.stats)
    if group_filter is not None:
        q = q.where(ReportRun.group_id == group_filter)
    rows = (await db.execute(q.order_by(ReportRun.created_at.desc()).limit(limit))).all()
    return [{"id": str(r.id), "period_from": r.period_from.isoformat(), "period_to": r.period_to.isoformat(),
             "language": r.language, "ai": bool(r.narrative), "created_by_name": r.created_by_name,
             "created_at": r.created_at.isoformat(), "pdf_sha256": r.pdf_sha256,
             "alerts": (r.stats or {}).get("alerts", {}).get("total"),
             "cases": (r.stats or {}).get("cases", {}).get("opened")} for r in rows]


@router.get("/history/{run_id}/pdf")
async def report_history_pdf(
    run_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    run = await db.get(ReportRun, run_id)
    if run is None or (group_filter is not None and run.group_id != group_filter):
        raise HTTPException(404, "Report not found")
    name = f"security-report-{run.period_from:%Y-%m-%d}.pdf"
    return Response(content=run.pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
