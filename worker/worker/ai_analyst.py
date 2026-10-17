# worker/worker/ai_analyst.py
"""
AI SOC L1 Analyst — aktif mentriage setiap alert, bukan hanya memfilter.

Alur per alert:
1. TI enrichment (best-effort, tidak berhenti jika gagal)
2. Groq L1 triage → verdict: escalate | create_case | monitor | false_positive
3. Tulis triage notes langsung ke alert (AlertNote)
4. Acknowledge alert (update status + acknowledged_at)
5. Handle verdict:
   - escalate/create_case : cek duplicate case → link atau buat baru → campaign analyzer
   - monitor              : cukup acknowledge + notes
   - false_positive       : close alert + tulis alasan
"""
import asyncio
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, update

from worker.database import AsyncSessionLocal
from worker.models import Alert, AlertNote, Case, CaseNote, ThreatHunt
from worker.llm_client import analyze_alert_with_ai
from worker.alert_manager import dispatch_case_webhooks
from worker.settings_cache import get_setting
from worker.ti.config import TIConfig
from worker.ti.aggregator import EnrichmentAggregator
from worker.ti.mitre import suggest_mitre, stage_for_techniques
from worker.campaign_analyzer import analyze_campaign
from worker.searxng_client import search_threat_intel
from worker.ninerouter_search import search_via_9router
from worker.web_fetch import fetch_page_text
from worker.fleet_correlation import check_fleet_spread, LOOKBACK_HOURS as FLEET_LOOKBACK_HOURS
from worker.rag import retrieve_similar_cases, retrieve_sop_context, retrieve_feedback_context
from worker.soar_engine import run_soar_playbooks

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
        shodan_api_key=await get_setting("shodan_api_key"),
        searxng_url=await get_setting("searxng_url", "http://searxng:8080"),
    )


_FIELD_SYNTAX = re.compile(
    r"\b(?:src_ip|source_ip|dst_ip|dest_ip|dest_host|uri|url|hostname|host|agent_id|"
    r"index|source\.ip|destination\.ip|http\.request\.uri|user\.name|event\.action)\b"
    r"\s*(?:[:=]|\bCONTAINS\b|\bLIKE\b|\bMATCH\b)",
    re.I,
)
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|127|169\.254|192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}(?:\.\d{1,3})?\b"
)
_OUR_HOSTNAMES = re.compile(r"\bagent-demo\b", re.I)
_SPLUNK_PIPE = re.compile(r"\|\s*(?:stats|table|eval|dedup|sort)\b", re.I)


def _is_internal_query(query: str) -> bool:
    return bool(
        not query
        or _FIELD_SYNTAX.search(query)
        or _PRIVATE_IP.search(query)
        or _OUR_HOSTNAMES.search(query)
        or _SPLUNK_PIPE.search(query)
    )


def _derive_public_query(*parts: Optional[str]) -> Optional[str]:
    """Build a public-safe query from an alert's own description.

    Used when the model supplies only telemetry filters: the alert title and
    MITRE technique are always safe to search for and still describe the threat,
    so the analyst gets research instead of silence.
    """
    chunks: list[str] = []
    for part in parts:
        if not part:
            continue
        text = _PRIVATE_IP.sub(" ", str(part))
        text = _OUR_HOSTNAMES.sub(" ", text)
        text = _FIELD_SYNTAX.sub(" ", text)
        text = _SPLUNK_PIPE.sub(" ", text)
        text = re.sub(r"[^\w\s\-/.:]", " ", text)
        text = " ".join(text.split())
        if text:
            chunks.append(text[:90])
    if not chunks:
        return None
    derived = " ".join(chunks)
    return derived if not _is_internal_query(derived) else None


def _sanitize_search_query(query: str) -> str | None:
    """Return the query if it is usable as a public web search, else None.

    The model sometimes expresses local telemetry as a query over our own
    fields ("src_ip=203.0.113.19 AND uri=*.env*", "index=auth host=agent-demo",
    "| stats count by user"). Those are correct for analysis but the public
    search backend rejects them as internal lookups, so they are discarded here
    and _run_ai_searches falls back to a query derived from the alert itself.
    """
    if not query:
        return None
    if _is_internal_query(query):
        return None
    return " ".join(query.split()) or None


async def _run_ai_searches(
    alert_id: str,
    case_id: Optional[str],
    search_queries: list[str],
    *,
    alert_title: Optional[str] = None,
    mitre_techniques: Optional[list[str]] = None,
) -> None:
    """
    Jalankan SearXNG dengan query yang dipilih AI sendiri,
    lalu tambahkan hasilnya ke alert note (dan case note jika ada).
    """
    queries = [_sanitize_search_query(q) for q in (search_queries or [])]
    queries = [q for q in queries if q]

    if not queries:
        derived = _derive_public_query(alert_title, (mitre_techniques or [None])[0])
        if derived:
            queries = [derived]
            log.info("ai_search_query_derived", alert_id=alert_id, query=derived)
        else:
            log.info("ai_search_no_usable_query", alert_id=alert_id)
            return
    else:
        skipped = len(search_queries) - len(queries)
        if skipped:
            log.info("ai_search_queries_filtered", alert_id=alert_id, kept=len(queries), dropped=skipped)

    all_results = []
    for safe_query in queries[:3]:
        # Prefer 9router's /v1/search (multi-provider auto-fallback if a
        # search-combo is configured); fall back to direct SearXNG on failure.
        results = await search_via_9router(safe_query, num_results=4)
        if not results:
            results = await search_threat_intel(safe_query, num_results=4)
        if results:
            all_results.append((safe_query, results))
        await asyncio.sleep(0.5)

    if not all_results:
        return

    # Susun catatan dari hasil pencarian
    lines = ["## 🔎 AI Web Research"]
    lines.append("*Query chosen by the AI based on alert context.*\n")
    for query, results in all_results:
        lines.append(f"**Query:** `{query}`")
        for idx, r in enumerate(results[:3]):
            title = r.get("title", "")
            url = r.get("url", "")
            content = r.get("content", "")[:250]
            # Actually browse the top result instead of relying on the
            # search engine's short snippet — gives the analyst (and the
            # RAG index, via case notes) the real advisory/bulletin text.
            if idx == 0 and url:
                page_text = await fetch_page_text(url)
                if page_text:
                    content = page_text
            lines.append(f"- **{title}**")
            if content:
                lines.append(f"  {content}")
            if url:
                lines.append(f"  🔗 {url}")
        lines.append("")

    search_note = "\n".join(lines)

    # Tulis ke alert note
    await _write_alert_note(alert_id, search_note)

    # Juga tambahkan ke case note jika ada case
    if case_id:
        try:
            async with AsyncSessionLocal() as db:
                note = CaseNote(
                    case_id=uuid.UUID(case_id),
                    author_id=None,
                    content=search_note,
                    is_ai_generated=True,
                )
                db.add(note)
                await db.commit()
        except Exception as exc:
            log.warning("search_case_note_failed", case_id=case_id, error=str(exc))

    log.info("ai_searches_completed",
             alert_id=alert_id,
             query_count=len(all_results),
             queries=[q for q, _ in all_results])


async def _write_alert_note(alert_id: str, content: str) -> None:
    """Tulis catatan triage AI langsung ke alert. No-op jika alert_id kosong (misal UEBA)."""
    if not alert_id:
        return
    try:
        async with AsyncSessionLocal() as db:
            note = AlertNote(
                alert_id=uuid.UUID(alert_id),
                author_id=None,
                content=content,
            )
            db.add(note)
            await db.commit()
    except Exception as exc:
        log.warning("alert_note_write_failed", alert_id=alert_id, error=str(exc))


async def _tag_alert_with_mitre(alert_id: str, mitre_techniques: list[str]) -> None:
    """Persist AI-derived MITRE techniques + kill-chain stage onto the alert row.

    Written for every triage verdict (not just case-creating ones) so the
    case attack-graph timeline can place every related alert in its lane,
    including ones that ended up monitor/false_positive.
    """
    if not alert_id or not mitre_techniques:
        return
    try:
        async with AsyncSessionLocal() as db:
            alert = await db.get(Alert, uuid.UUID(alert_id))
            if alert:
                alert.mitre_techniques = mitre_techniques
                alert.kill_chain_stage = stage_for_techniques(mitre_techniques)
                await db.commit()
    except Exception as exc:
        log.warning("alert_mitre_tag_failed", alert_id=alert_id, error=str(exc))


async def _set_alert_verdict(alert_id: str, verdict: str) -> None:
    """Stash the AI's verdict on the alert row itself so it survives past
    triage (used by the /feedback endpoint to know what the AI actually
    decided when an analyst rates it later)."""
    if not alert_id:
        return
    try:
        async with AsyncSessionLocal() as db:
            alert = await db.get(Alert, uuid.UUID(alert_id))
            if alert:
                alert.ai_verdict = verdict
                await db.commit()
    except Exception as exc:
        log.warning("set_alert_verdict_failed", alert_id=alert_id, error=str(exc))


async def _update_alert_status(alert_id: str, status: str) -> None:
    """Update status alert + set acknowledged_at jika belum di-set. No-op jika alert_id kosong."""
    if not alert_id:
        return
    try:
        async with AsyncSessionLocal() as db:
            alert = await db.get(Alert, uuid.UUID(alert_id))
            if alert:
                alert.status = status
                if not alert.acknowledged_at:
                    alert.acknowledged_at = datetime.now(timezone.utc)
                if status in ("closed", "resolved"):
                    alert.resolved_at = datetime.now(timezone.utc)
                await db.commit()
    except Exception as exc:
        log.warning("alert_status_update_failed", alert_id=alert_id, error=str(exc))


async def _find_existing_open_case(
    source_ip: Optional[str],
    hostname: Optional[str],
    group_id: str,
) -> Optional[str]:
    """Cari open case yang sudah ada untuk entity yang sama (24 jam terakhir)."""
    if not source_ip and not hostname:
        return None
    window = datetime.now(timezone.utc) - timedelta(hours=24)
    async with AsyncSessionLocal() as db:
        q = select(Case).where(
            Case.group_id == group_id,
            Case.status == "open",
            Case.created_at >= window,
            Case.created_by_ai == True,
        )
        cases = (await db.execute(q)).scalars().all()
        for case in cases:
            ioc = case.ioc_data or {}
            if source_ip and ioc.get("source_ip") == source_ip:
                return str(case.id)
            if hostname and ioc.get("hostname") == hostname:
                return str(case.id)
    return None


async def _check_and_note_fleet_spread(
    case_id: str,
    title: str,
    group_id: str,
    hostname: Optional[str],
) -> None:
    """Check if this same alert also fired on other hosts recently, and if
    so, write a note so the analyst knows this isn't an isolated incident."""
    try:
        spread = await check_fleet_spread(title, group_id, hostname)
        if not spread:
            return
        hosts_list = "\n".join(f"- {h}" for h in spread["hostnames"])
        remainder = spread["host_count"] - len(spread["hostnames"])
        if remainder > 0:
            hosts_list += f"\n- …and {remainder} more"
        verdict_line = (
            "This looks like a coordinated or automated campaign across the fleet, not an isolated incident."
            if spread["host_count"] >= 3
            else "Worth checking whether these hosts share a common cause (same exposed service, same leaked credentials, etc)."
        )
        note_content = (
            f"## 🌐 Fleet-Wide Check\n\n"
            f"This same alert (**{title}**) also fired on **{spread['host_count']} other host(s)** "
            f"in the last {FLEET_LOOKBACK_HOURS}h:\n\n{hosts_list}\n\n{verdict_line}"
        )
        async with AsyncSessionLocal() as db:
            db.add(CaseNote(case_id=uuid.UUID(case_id), author_id=None, content=note_content, is_ai_generated=True))
            await db.commit()
        log.info("fleet_spread_detected", case_id=case_id, title=title, host_count=spread["host_count"])
    except Exception as exc:
        log.warning("fleet_spread_check_failed", case_id=case_id, error=str(exc))


async def _add_note_to_existing_case(
    case_id: str,
    alert_id: str,
    title: str,
    triage_notes: str,
    severity: str,
) -> None:
    """Tambah catatan ke case yang sudah ada (alert baru terkait kasus yang sama)."""
    async with AsyncSessionLocal() as db:
        note = CaseNote(
            case_id=uuid.UUID(case_id),
            author_id=None,
            content=(
                f"**[AI L1] New alert linked to this case**\n\n"
                f"Alert: {title} | Severity: {severity}\n\n"
                f"**Triage notes:**\n{triage_notes}"
            ),
            is_ai_generated=True,
        )
        db.add(note)
        await db.commit()
    log.info("alert_linked_to_existing_case", case_id=case_id, alert_id=alert_id)


async def _create_case_from_verdict(
    alert_id: str,
    title: str,
    severity: str,
    verdict: str,
    analysis: dict,
    enrichment,
    group_id: str,
) -> Optional[str]:
    """Buat case baru dari hasil triage."""
    triage_notes = analysis.get("triage_notes", "")
    mitre = analysis.get("mitre_techniques", [])
    actions = analysis.get("immediate_actions", [])
    confidence = analysis.get("confidence", 0.0)
    threat_type = analysis.get("threat_type", "other")

    ioc_data: dict = {
        "threat_type": threat_type,
        "mitre_techniques": mitre,
        "verdict": verdict,
    }
    if enrichment:
        ioc_data["source_ip"] = getattr(enrichment, "source_ip", None)
        ioc_data["extracted_iocs"] = [
            {"type": i.type.value, "value": i.value}
            for i in enrichment.iocs[:20]
        ]
        ioc_data["overall_risk"] = enrichment.overall_risk

    search_intel: dict = {}
    if enrichment and enrichment.provider_bullets:
        non_searx = [b for b in enrichment.provider_bullets if not b.startswith("searxng:")][:10]
        search_intel["ti_bullets"] = non_searx
        if enrichment.overall_risk > 0:
            search_intel["ti_risk"] = enrichment.overall_risk

    # Different prefix for escalate vs create_case
    prefix = "🚨 [ESCALATED]" if verdict == "escalate" else "[AI]"
    case_status = "open"

    async with AsyncSessionLocal() as db:
        try:
            alert_uuid = uuid.UUID(alert_id) if alert_id else None
        except ValueError:
            alert_uuid = None
        case = Case(
            title=f"{prefix} {title}",
            description=triage_notes,
            severity=severity,
            status=case_status,
            alert_id=alert_uuid,
            ai_reasoning=triage_notes,
            ai_confidence=confidence,
            ioc_data=ioc_data,
            search_intel=search_intel,
            created_by_ai=True,
            group_id=group_id,
        )
        db.add(case)
        await db.flush()

        # Bangun note lengkap dari perspektif L1 analyst
        ti_section = ""
        if enrichment and enrichment.provider_bullets:
            bullets = [b for b in enrichment.provider_bullets if not b.startswith("searxng:")][:8]
            if bullets:
                ti_section = "\n\n**Threat Intel:**\n" + "\n".join(f"- {b}" for b in bullets)
            if enrichment.overall_risk > 0:
                ti_section += f"\n\n**TI Risk Score:** {enrichment.overall_risk:.2f}"

        mitre_section = ""
        if mitre:
            mitre_section = "\n\n**MITRE ATT&CK:**\n" + "\n".join(f"- {t}" for t in mitre)

        actions_section = ""
        if actions:
            actions_section = "\n\n**Immediate Actions:**\n" + "\n".join(f"- {a}" for a in actions)

        verdict_label = "🚨 ESCALATED — Needs L2 attention NOW" if verdict == "escalate" else "📋 Case created for L2 review"

        note_content = (
            f"## AI SOC L1 Analyst — Triage Report\n\n"
            f"**Verdict:** {verdict_label}\n"
            f"**Confidence:** {confidence:.0%}\n"
            f"**Threat Type:** {threat_type}\n\n"
            f"**Investigation Notes:**\n{triage_notes}"
            f"{ti_section}{mitre_section}{actions_section}"
        )

        note = CaseNote(
            case_id=case.id,
            author_id=None,
            content=note_content,
            is_ai_generated=True,
        )
        db.add(note)
        await db.commit()
        log.info("case_created_by_ai_l1",
                 case_id=str(case.id),
                 verdict=verdict,
                 confidence=confidence,
                 threat_type=threat_type)
        return str(case.id)


async def _maybe_enqueue_hunt(source_ip: str, group_id: str) -> None:
    """Enqueue a ThreatHunt for source_ip if not already hunted in last 24h."""
    window = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        async with AsyncSessionLocal() as db:
            existing = (await db.execute(
                select(ThreatHunt).where(
                    ThreatHunt.ioc_type == "ip",
                    ThreatHunt.ioc_value == source_ip,
                    ThreatHunt.group_id == group_id,
                    ThreatHunt.created_at >= window,
                )
            )).scalars().first()
            if existing:
                log.debug("hunt_skip_recent", source_ip=source_ip)
                return
            hunt = ThreatHunt(
                ioc_type="ip",
                ioc_value=source_ip,
                group_id=group_id,
            )
            db.add(hunt)
            await db.commit()
            log.info("hunt_enqueued_by_ai", source_ip=source_ip, group_id=group_id)
    except Exception as exc:
        log.warning("hunt_enqueue_failed", source_ip=source_ip, error=str(exc))


async def _graph_enrich(text_blob: str, alert_title: str):
    """Adapter so the triage graph can call TI enrichment without knowing how
    the aggregator is constructed."""
    cfg = await _build_ti_config()
    aggregator = EnrichmentAggregator(cfg)
    return await aggregator.enrich(text_blob, alert_title=alert_title)


async def analyze_and_maybe_create_case(
    alert_id: str,
    title: str,
    severity: str,
    source_ip: Optional[str],
    hostname: Optional[str],
    decoded_fields: dict,
    group_id: str,
) -> None:
    enabled = await get_setting("ai_analyst_enabled", "true")
    if enabled.lower() == "false":
        return

    from worker.config import NINEROUTER_API_KEY, NINEROUTER_BASE_URL, NINEROUTER_MODEL
    from worker.graph.checkpoint import triage_lock
    from worker.graph.triage_graph import build_triage_graph
    from worker.redis_client import get_redis

    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    if not api_key:
        log.warning("ai_triage_skipped", alert_id=alert_id, reason="no 9router api key")
        return
    model = await get_setting("ninerouter_model", NINEROUTER_MODEL)

    graph = build_triage_graph(
        base_url=NINEROUTER_BASE_URL,
        api_key=api_key,
        model=model,
        deps={
            "enrich": _graph_enrich,
            "escalate_severity": _escalate_severity,
            "suggest_mitre": suggest_mitre,
            "retrieve_similar_cases": retrieve_similar_cases,
            "retrieve_sop_context": retrieve_sop_context,
            "retrieve_feedback_context": retrieve_feedback_context,
            "enqueue_hunt": _maybe_enqueue_hunt,
            "get_setting": get_setting,
            "set_alert_verdict": _set_alert_verdict,
            "write_alert_note": _write_alert_note,
            "tag_alert_with_mitre": _tag_alert_with_mitre,
            "run_soar_playbooks": run_soar_playbooks,
            "update_alert_status": _update_alert_status,
            "run_searches": _run_ai_searches,
            "find_existing_open_case": _find_existing_open_case,
            "add_note_to_existing_case": _add_note_to_existing_case,
            "create_case_from_verdict": _create_case_from_verdict,
            "analyze_campaign": analyze_campaign,
            "check_fleet_spread": _check_and_note_fleet_spread,
            "dispatch_case_webhooks": dispatch_case_webhooks,
        },
    )

    state = {
        "alert_id": alert_id,
        "title": title,
        "severity": severity,
        "source_ip": source_ip,
        "hostname": hostname,
        "decoded_fields": decoded_fields,
        "group_id": group_id,
        "similar_cases": [],
        "sop_context": [],
        "feedback_context": [],
    }

    # One replica owns each alert's triage; the other skips rather than
    # double-creating a case or double-firing SOAR actions.
    redis = await get_redis()
    async with triage_lock(redis, alert_id) as owned:
        if not owned:
            log.info("ai_triage_already_running", alert_id=alert_id)
            return
        await graph.ainvoke(
            state, {"configurable": {"thread_id": f"triage-{alert_id}"}}
        )
