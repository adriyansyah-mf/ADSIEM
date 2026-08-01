# server-api/app/services/report_pdf.py
"""Builds the on-demand security report PDF from pre-gathered stats — no DB
or network access happens here, this is pure rendering."""
import io
from datetime import date

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#64748b"),
}


def build_report_pdf(
    org_name: str,
    date_from: date,
    date_to: date,
    generated_at: str,
    narrative: str,
    total_alerts: int,
    severity_counts: dict[str, int],
    top_rules: list[tuple[str, int]],
    verdict_counts: dict[str, int],
    top_mitre: list[str],
    total_cases: int,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=16, spaceAfter=8,
                         textColor=colors.HexColor("#1e293b"))
    meta = ParagraphStyle("meta", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"))
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, leading=15)

    story = []
    story.append(Paragraph(org_name or "Security Report", h1))
    story.append(Paragraph("Security Operations Report", meta))
    story.append(Paragraph(f"Period: {date_from.isoformat()} to {date_to.isoformat()}", meta))
    story.append(Paragraph(f"Generated: {generated_at}", meta))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e2e8f0")))

    if narrative:
        story.append(Paragraph("Executive Summary", h2))
        for para in narrative.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip().replace("\n", "<br/>"), body))
                story.append(Spacer(1, 6))

    story.append(Paragraph("Overview", h2))
    overview_rows = [["Metric", "Value"],
                     ["Total Alerts", str(total_alerts)],
                     ["Total Cases", str(total_cases)]]
    story.append(_styled_table(overview_rows, [10 * cm, 5 * cm]))

    if severity_counts:
        story.append(Paragraph("Alerts by Severity", h2))
        rows = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            n = severity_counts.get(sev, 0)
            if n:
                rows.append([sev.upper(), str(n)])
        story.append(_styled_table(rows, [10 * cm, 5 * cm]))

    if top_rules:
        story.append(Paragraph("Top Triggered Rules", h2))
        rows = [["Rule", "Count"]] + [[name, str(count)] for name, count in top_rules]
        story.append(_styled_table(rows, [12 * cm, 3 * cm]))

    if verdict_counts:
        story.append(Paragraph("AI Verdict Distribution", h2))
        rows = [["Verdict", "Count"]] + [[v.replace("_", " ").title(), str(c)] for v, c in verdict_counts.items()]
        story.append(_styled_table(rows, [10 * cm, 5 * cm]))

    if top_mitre:
        story.append(Paragraph("MITRE ATT&CK Techniques Observed", h2))
        story.append(Paragraph(", ".join(top_mitre), body))

    doc.build(story)
    return buf.getvalue()


def _styled_table(rows: list[list[str]], col_widths: list[float]) -> Table:
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    return t
