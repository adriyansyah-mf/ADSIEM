# worker/worker/ai_analyst.py
import asyncio
import json
import uuid
import structlog
from datetime import datetime, timezone
from sqlalchemy import select
from worker.database import AsyncSessionLocal
from worker.models import Alert, Case, CaseNote
from worker.groq_client import analyze_alert_with_groq
from worker.searxng_client import search_threat_intel
from worker.config import GROQ_API_KEY

log = structlog.get_logger()

async def analyze_and_maybe_create_case(
    alert_id: str,
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    group_id: str,
) -> None:
    search_results = []
    if source_ip and GROQ_API_KEY:
        search_results = await search_threat_intel(f"threat intelligence {source_ip} malicious")
    elif title and GROQ_API_KEY:
        search_results = await search_threat_intel(f"cyber threat {title} MITRE ATT&CK")

    analysis = await analyze_alert_with_groq(
        title=title,
        severity=severity,
        source_ip=source_ip,
        hostname=hostname,
        decoded_fields=decoded_fields,
        search_results=search_results,
    )

    log.info("ai_analysis_complete",
             alert_id=alert_id,
             should_create_case=analysis.get("should_create_case"),
             confidence=analysis.get("confidence"))

    if not analysis.get("should_create_case"):
        return

    async with AsyncSessionLocal() as db:
        alert_uuid = uuid.UUID(alert_id) if alert_id else None
        case = Case(
            title=f"[AI] {title}",
            description=analysis.get("reasoning"),
            severity=severity,
            status="open",
            alert_id=alert_uuid,
            ai_reasoning=analysis.get("reasoning"),
            ioc_data=analysis.get("ioc_summary", {}),
            search_intel={"results": search_results},
            created_by_ai=True,
            group_id=group_id,
        )
        db.add(case)
        await db.flush()
        note = CaseNote(
            case_id=case.id,
            author_id=None,
            content=f"**AI SOC L1 Analysis**\n\n{analysis.get('reasoning')}\n\nConfidence: {analysis.get('confidence', 0):.0%}",
            is_ai_generated=True,
        )
        db.add(note)
        await db.commit()
        log.info("case_created_by_ai", case_id=str(case.id), title=case.title)
