# worker/worker/ai_analyst.py
import json
import uuid
import structlog
from worker.database import AsyncSessionLocal
from worker.models import Case, CaseNote
from worker.groq_client import analyze_alert_with_groq
from worker.alert_manager import dispatch_case_webhooks
from worker.settings_cache import get_setting
from worker.ti.config import TIConfig
from worker.ti.aggregator import EnrichmentAggregator
from worker.ti.mitre import suggest_mitre

log = structlog.get_logger()

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"]


def _escalate_severity(base: str, overall_risk: float) -> str:
    idx = _SEVERITY_ORDER.get(base.lower(), 2)
    if overall_risk >= 0.75:
        idx = min(4, idx + 2)
    elif overall_risk >= 0.45:
        idx = min(4, idx + 1)
    return _SEVERITY_NAMES[idx]


async def _build_ti_config() -> TIConfig:
    return TIConfig(
        virustotal_api_key=await get_setting("virustotal_api_key"),
        abuseipdb_api_key=await get_setting("abuseipdb_api_key"),
        otx_api_key=await get_setting("otx_api_key"),
        greynoise_api_key=await get_setting("greynoise_api_key"),
        searxng_url=await get_setting("searxng_url", "http://searxng:8080"),
    )


async def analyze_and_maybe_create_case(
    alert_id: str,
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    group_id: str,
) -> None:
    enabled = await get_setting("ai_analyst_enabled", "true")
    if enabled.lower() == "false":
        return

    # Build enrichment context from raw alert text
    text_blob = "\n".join(filter(None, [
        title,
        source_ip,
        hostname,
        json.dumps(decoded_fields, default=str)[:800],
    ]))

    cfg = await _build_ti_config()
    aggregator = EnrichmentAggregator(cfg)

    try:
        enrichment = await aggregator.enrich(text_blob, alert_title=title)
    except Exception as e:
        log.warning("enrichment_failed", error=str(e))
        enrichment = None

    # Heuristic MITRE from alert text
    heuristic_mitre = suggest_mitre(text_blob)

    # Effective severity after TI escalation
    effective_severity = severity
    if enrichment and enrichment.overall_risk > 0:
        effective_severity = _escalate_severity(severity, enrichment.overall_risk)
        if effective_severity != severity:
            log.info("severity_escalated",
                     original=severity, escalated=effective_severity,
                     risk=enrichment.overall_risk)

    analysis = await analyze_alert_with_groq(
        title=title,
        severity=effective_severity,
        source_ip=source_ip,
        hostname=hostname,
        decoded_fields=decoded_fields,
        enrichment=enrichment,
        heuristic_mitre=heuristic_mitre,
    )

    log.info("ai_analysis_complete",
             alert_id=alert_id,
             should_create_case=analysis.get("should_create_case"),
             confidence=analysis.get("confidence"),
             overall_risk=enrichment.overall_risk if enrichment else 0,
             ioc_count=len(enrichment.iocs) if enrichment else 0)

    if not analysis.get("should_create_case"):
        log.info("ai_no_case",
                 alert_id=alert_id,
                 reasoning=analysis.get("reasoning", ""),
                 confidence=analysis.get("confidence", 0))
        return

    ioc_data = analysis.get("ioc_summary", {})
    if enrichment:
        ioc_data["extracted_iocs"] = [
            {"type": i.type.value, "value": i.value}
            for i in enrichment.iocs[:20]
        ]
        ioc_data["overall_risk"] = enrichment.overall_risk
        if heuristic_mitre:
            existing = ioc_data.get("mitre_techniques") or []
            if isinstance(existing, str):
                existing = [existing]
            ioc_data["mitre_techniques"] = sorted(set(existing + heuristic_mitre))

    search_intel = {}
    if enrichment:
        searxng_bullets = [b for b in enrichment.provider_bullets if b.startswith("searxng:")]
        if searxng_bullets:
            search_intel["searxng_context"] = searxng_bullets[0]
        search_intel["ti_bullets"] = [b for b in enrichment.provider_bullets if not b.startswith("searxng:")][:10]

    async with AsyncSessionLocal() as db:
        alert_uuid = uuid.UUID(alert_id) if alert_id else None
        reasoning = analysis.get("reasoning", "")
        case = Case(
            title=f"[AI] {title}",
            description=reasoning,
            severity=effective_severity,
            status="open",
            alert_id=alert_uuid,
            ai_reasoning=reasoning,
            ioc_data=ioc_data,
            search_intel=search_intel,
            created_by_ai=True,
            group_id=group_id,
        )
        db.add(case)
        await db.flush()

        ti_summary = ""
        if enrichment and enrichment.provider_bullets:
            non_searx = [b for b in enrichment.provider_bullets if not b.startswith("searxng:")][:8]
            if non_searx:
                ti_summary = "\n\n**Threat Intel:**\n" + "\n".join(f"- {b}" for b in non_searx)
            if enrichment.overall_risk > 0:
                ti_summary += f"\n\n**TI Risk Score:** {enrichment.overall_risk:.2f}"

        note = CaseNote(
            case_id=case.id,
            author_id=None,
            content=f"**AI SOC L1 Analysis**\n\n{reasoning}\n\nConfidence: {analysis.get('confidence', 0):.0%}{ti_summary}",
            is_ai_generated=True,
        )
        db.add(note)
        await db.commit()
        log.info("case_created_by_ai", case_id=str(case.id), title=case.title)

    try:
        await dispatch_case_webhooks(
            case_id=str(case.id),
            title=case.title,
            severity=case.severity,
            description=reasoning[:500] if reasoning else "",
            group_id=group_id,
            alert_id=alert_uuid,
        )
    except Exception as _e:
        log.warning("case_webhook_dispatch_failed", error=str(_e))
