# server-api/app/api/routes/export.py
import csv
import io
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, Case, User

router = APIRouter(prefix="/api/export", tags=["export"])

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _safe_csv(v: str) -> str:
    if v and v[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + v
    return v


# ── Alerts CSV ───────────────────────────────────────────────────

@router.get("/alerts/csv")
async def export_alerts_csv(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=1000, le=5000),
):
    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    result = await db.execute(q)
    alerts = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "source_ip", "hostname", "group_id", "created_at"])
    for a in alerts:
        writer.writerow([
            str(a.id), _safe_csv(a.title), a.severity, a.status,
            a.source_ip or "", _safe_csv(a.hostname or ""), a.group_id,
            a.created_at.isoformat() if a.created_at else "",
        ])
    output.seek(0)
    filename = f"alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Alerts PDF ───────────────────────────────────────────────────

@router.get("/alerts/pdf")
async def export_alerts_pdf(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=200, le=1000),
):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm

    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    result = await db.execute(q)
    alerts = result.scalars().all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=1*cm, rightMargin=1*cm,
                             topMargin=1.5*cm, bottomMargin=1*cm)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SIEM Platform — Alerts Report", styles["Title"]))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  Total: {len(alerts)}",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.5*cm))

    _SEV_COLORS = {
        "critical": colors.HexColor("#E74C3C"),
        "high":     colors.HexColor("#E67E22"),
        "medium":   colors.HexColor("#F1C40F"),
        "low":      colors.HexColor("#3498DB"),
        "info":     colors.HexColor("#95A5A6"),
    }

    table_data = [["Severity", "Title", "Status", "Source IP", "Hostname", "Time"]]
    for a in alerts:
        ts = a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else ""
        table_data.append([
            a.severity.upper(),
            (a.title[:60] + "…") if len(a.title) > 60 else a.title,
            a.status, a.source_ip or "—", a.hostname or "—", ts,
        ])

    col_widths = [2.5*cm, 9*cm, 2.5*cm, 3.5*cm, 3.5*cm, 4*cm]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",    (0, 0), (-1, 0), 8),
        ("FONTSIZE",    (0, 1), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f1117"), colors.HexColor("#151c28")]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#1e293b")),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])
    for i, a in enumerate(alerts, start=1):
        c = _SEV_COLORS.get(a.severity, colors.gray)
        style.add("TEXTCOLOR", (0, i), (0, i), c)
    table.setStyle(style)
    elements.append(table)

    doc.build(elements)
    buf.seek(0)
    filename = f"alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        iter([buf.read()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Cases CSV ────────────────────────────────────────────────────

@router.get("/cases/csv")
async def export_cases_csv(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    limit: int = Query(default=1000, le=5000),
):
    q = select(Case).order_by(Case.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Case.group_id == group_filter)
    result = await db.execute(q)
    cases = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "created_by_ai", "group_id", "created_at"])
    for c in cases:
        writer.writerow([
            str(c.id), _safe_csv(c.title), c.severity, c.status,
            str(c.created_by_ai), c.group_id,
            c.created_at.isoformat() if c.created_at else "",
        ])
    output.seek(0)
    filename = f"cases_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
