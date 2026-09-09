# server-api/app/api/routes/reports.py
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.llm_client import generate_text
from app.models.models import Alert, PlatformSetting
from app.schemas.schemas import ReportGenerateRequest
from app.services.report_pdf import build_report_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])
Perm = require_permission("alerts:read")


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return (row.value if row and row.value else default)


@router.post("/generate")
async def generate_report(
    body: ReportGenerateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    range_from = datetime.combine(body.date_from, datetime.min.time(), tzinfo=timezone.utc)
    range_to = datetime.combine(body.date_to, datetime.max.time(), tzinfo=timezone.utc)

    alert_q = select(Alert).where(Alert.created_at >= range_from, Alert.created_at <= range_to)
    if group_filter:
        alert_q = alert_q.where(Alert.group_id == group_filter)
    alerts = (await db.execute(alert_q)).scalars().all()

    severity_counts = dict(Counter(a.severity for a in alerts))
    top_rules = Counter(a.title for a in alerts).most_common(10)

    case_filter_sql = "AND group_id = :group_id" if group_filter else ""
    params = {"date_from": range_from, "date_to": range_to}
    if group_filter:
        params["group_id"] = group_filter

    verdict_rows = (await db.execute(text(f"""
        SELECT COALESCE(ioc_data->>'verdict', 'unknown') AS verdict, COUNT(*) AS cnt
        FROM cases
        WHERE created_at >= :date_from AND created_at <= :date_to
          AND created_by_ai = TRUE {case_filter_sql}
        GROUP BY COALESCE(ioc_data->>'verdict', 'unknown')
    """), params)).mappings().all()
    verdict_counts = {r["verdict"]: r["cnt"] for r in verdict_rows}

    mitre_rows = (await db.execute(text(f"""
        SELECT DISTINCT jsonb_array_elements_text(ioc_data->'mitre_techniques') AS technique
        FROM cases
        WHERE created_at >= :date_from AND created_at <= :date_to
          AND created_by_ai = TRUE AND ioc_data ? 'mitre_techniques' {case_filter_sql}
        LIMIT 15
    """), params)).mappings().all()
    top_mitre = [r["technique"] for r in mitre_rows]

    total_cases_row = (await db.execute(text(f"""
        SELECT COUNT(*) AS cnt FROM cases
        WHERE created_at >= :date_from AND created_at <= :date_to {case_filter_sql}
    """), params)).mappings().first()
    total_cases = total_cases_row["cnt"] if total_cases_row else 0

    org_name = await _get_setting(db, "org_name", "SIEM Security Report")
    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")

    prompt = f"""You are an AI SOC analyst writing an executive security report.

Data for the period {body.date_from.isoformat()} to {body.date_to.isoformat()}:
- Total alerts: {len(alerts)}
- Total cases: {total_cases}
- Severity breakdown: {json.dumps(severity_counts)}
- AI verdict distribution: {json.dumps(verdict_counts)}
- MITRE ATT&CK techniques observed: {top_mitre}

Write a 3-paragraph executive summary IN {body.language.upper()} (the entire response must be in {body.language}):
1. Overview of the period's threat landscape
2. Key findings (campaigns detected, top techniques, notable patterns)
3. Recommended focus areas going forward

Keep it concise — max 220 words total. No bullet points, pure paragraphs. Respond with plain text only, no markdown."""

    # Close the read transaction (all the queries above) before the LLM call,
    # which can take 60-90s+ on a slow/retrying provider — an open
    # transaction for that long can block unrelated DDL elsewhere.
    await db.commit()
    narrative = await generate_text(api_key, model, prompt, max_tokens=2000)

    pdf_bytes = build_report_pdf(
        org_name=org_name,
        date_from=body.date_from,
        date_to=body.date_to,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        narrative=narrative,
        total_alerts=len(alerts),
        severity_counts=severity_counts,
        top_rules=top_rules,
        verdict_counts=verdict_counts,
        top_mitre=top_mitre,
        total_cases=total_cases,
    )

    filename = f"security-report-{body.date_from.isoformat()}-to-{body.date_to.isoformat()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
