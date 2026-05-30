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
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, update

from worker.database import AsyncSessionLocal
from worker.models import Alert, AlertNote, Case, CaseNote, ThreatHunt
from worker.groq_client import analyze_alert_with_groq
from worker.alert_manager import dispatch_case_webhooks
from worker.settings_cache import get_setting
from worker.ti.config import TIConfig
from worker.ti.aggregator import EnrichmentAggregator
from worker.ti.mitre import suggest_mitre
from worker.campaign_analyzer import analyze_campaign
from worker.searxng_client import search_threat_intel
from worker.rag import retrieve_similar_cases, retrieve_sop_context
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
        searxng_url=await get_setting("searxng_url", "http://searxng:8080"),
    )


async def _run_ai_searches(
    alert_id: str,
    case_id: Optional[str],
    search_queries: list[str],
) -> None:
    """
    Jalankan SearXNG dengan query yang dipilih AI sendiri,
    lalu tambahkan hasilnya ke alert note (dan case note jika ada).
    """
    if not search_queries:
        return
    all_results = []
    for query in search_queries[:3]:
        results = await search_threat_intel(query, num_results=4)
        if results:
            all_results.append((query, results))
        await asyncio.sleep(0.5)

    if not all_results:
        return

    # Susun catatan dari hasil pencarian
    lines = ["## 🔎 AI Web Research (SearXNG)"]
    lines.append("*Query ditentukan oleh AI berdasarkan konteks alert.*\n")
    for query, results in all_results:
        lines.append(f"**Query:** `{query}`")
        for r in results[:3]:
            title = r.get("title", "")
            content = r.get("content", "")[:250]
            url = r.get("url", "")
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
                f"**[AI L1] Alert baru terkait case ini**\n\n"
                f"Alert: {title} | Severity: {severity}\n\n"
                f"**Catatan triage:**\n{triage_notes}"
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

    # Prefix berbeda untuk escalate vs create_case
    prefix = "🚨 [ESKALASI]" if verdict == "escalate" else "[AI]"
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
            actions_section = "\n\n**Aksi Segera:**\n" + "\n".join(f"- {a}" for a in actions)

        verdict_label = "🚨 ESKALASI — Butuh perhatian L2 SEGERA" if verdict == "escalate" else "📋 Case dibuat untuk review L2"

        note_content = (
            f"## AI SOC L1 Analyst — Laporan Triage\n\n"
            f"**Verdict:** {verdict_label}\n"
            f"**Confidence:** {confidence:.0%}\n"
            f"**Threat Type:** {threat_type}\n\n"
            f"**Catatan Investigasi:**\n{triage_notes}"
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

    _threshold_str = await get_setting("ai_confidence_threshold", "0.0")
    try:
        _confidence_threshold = float(_threshold_str)
    except (ValueError, TypeError):
        _confidence_threshold = 0.0

    # ── 1. TI enrichment (best-effort) ──────────────────────────────────────
    text_blob = "\n".join(filter(None, [title, source_ip, hostname,
                                        json.dumps(decoded_fields, default=str)[:800]]))
    cfg = await _build_ti_config()
    aggregator = EnrichmentAggregator(cfg)

    try:
        enrichment = await aggregator.enrich(text_blob, alert_title=title)
    except Exception as e:
        log.warning("enrichment_failed", error=str(e))
        enrichment = None

    # ── 2. Eskalasi severity dari TI ────────────────────────────────────────
    effective_severity = severity
    if enrichment and enrichment.overall_risk > 0:
        effective_severity = _escalate_severity(severity, enrichment.overall_risk)
        if effective_severity != severity:
            log.info("severity_escalated", original=severity, escalated=effective_severity)

    heuristic_mitre = suggest_mitre(text_blob)

    # ── 2b. Auto-enqueue threat hunt for malicious IPs ───────────────────────
    if source_ip and enrichment and enrichment.overall_risk > 0.5:
        asyncio.ensure_future(_maybe_enqueue_hunt(source_ip, group_id))

    # ── RAG — similar past cases ─────────────────────────────────────────────
    query_text = f"{title}\n{source_ip or ''}\n{hostname or ''}"
    similar_cases = await retrieve_similar_cases(query_text, group_id)
    if similar_cases:
        log.info("rag_similar_found", alert_id=alert_id, count=len(similar_cases),
                 top_similarity=round(float(similar_cases[0].get("similarity", 0)), 2))

    # ── RAG — SOP perusahaan ─────────────────────────────────────────────────
    sop_context = await retrieve_sop_context(query_text, group_id)
    if sop_context:
        log.info("rag_sop_found", alert_id=alert_id, chunks=len(sop_context))

    # ── 3. Groq L1 triage — selalu dijalankan ───────────────────────────────
    analysis = await analyze_alert_with_groq(
        title=title,
        severity=effective_severity,
        source_ip=source_ip,
        hostname=hostname,
        decoded_fields=decoded_fields,
        enrichment=enrichment,
        heuristic_mitre=heuristic_mitre,
        similar_cases=similar_cases if similar_cases else None,
        sop_context=sop_context if sop_context else None,
    )

    verdict = analysis.get("verdict", "monitor")
    triage_notes = analysis.get("triage_notes", "")
    confidence = analysis.get("confidence", 0.0)
    actions = analysis.get("immediate_actions", [])
    search_queries = analysis.get("search_queries", [])

    if confidence < _confidence_threshold and verdict not in ("monitor", "false_positive"):
        log.info("ai_low_confidence_downgrade",
                 alert_id=alert_id, confidence=confidence,
                 threshold=_confidence_threshold, original_verdict=verdict)
        verdict = "monitor"

    log.info("ai_l1_triage_done",
             alert_id=alert_id,
             verdict=verdict,
             severity=effective_severity,
             confidence=confidence)

    # ── 4. Tulis triage notes ke alert (selalu, apapun verdictnya) ──────────
    actions_str = ("\n\n**Aksi Segera:**\n" + "\n".join(f"- {a}" for a in actions)) if actions else ""
    note_content = (
        f"## 🤖 AI L1 Triage — {verdict.upper()}\n\n"
        f"**Confidence:** {confidence:.0%}\n\n"
        f"**Catatan Investigasi:**\n{triage_notes}"
        f"{actions_str}"
    )
    await _write_alert_note(alert_id, note_content)

    # ── 4c. Fire SOAR playbooks with AI context (fire-and-forget) ───────────
    if alert_id:
        try:
            alert_uuid = uuid.UUID(alert_id)
            rule_match_ctx = {
                "level": effective_severity,
                "title": title,
                "tags": decoded_fields.get("tags", []),
                "mitre_tags": analysis.get("mitre_techniques", []),
            }
            asyncio.ensure_future(run_soar_playbooks(
                alert_id=alert_uuid,
                rule_match=rule_match_ctx,
                source_ip=source_ip,
                hostname=hostname,
                user_name=decoded_fields.get("user.name"),
                group_id=group_id,
                ai_verdict=verdict,
                ai_confidence=confidence,
                ti_risk_score=enrichment.overall_risk if enrichment else None,
            ))
        except Exception as exc:
            log.warning("ai_soar_dispatch_failed", alert_id=alert_id, error=str(exc))

    # ── 4b. AI-driven web research (background, case_id belum ada di sini) ──
    # Search langsung dijalankan; case_id akan di-pass dari langkah 7 jika ada
    if search_queries:
        asyncio.ensure_future(_run_ai_searches(alert_id, None, search_queries))

    # ── 5. Update alert status berdasarkan verdict ───────────────────────────
    if verdict == "false_positive":
        fp_reason = analysis.get("false_positive_reason", "Ditentukan oleh AI L1")
        await _update_alert_status(alert_id, "closed")
        log.info("alert_closed_as_fp", alert_id=alert_id, reason=fp_reason)
        return

    if verdict == "monitor":
        await _update_alert_status(alert_id, "acknowledged")
        return

    # verdict == "create_case" atau "escalate"
    await _update_alert_status(alert_id, "acknowledged")

    # ── 6. Cek apakah sudah ada open case untuk entity yang sama ────────────
    existing_case_id = await _find_existing_open_case(source_ip, hostname, group_id)
    if existing_case_id:
        await _add_note_to_existing_case(
            existing_case_id, alert_id, title, triage_notes, effective_severity
        )
        asyncio.ensure_future(analyze_campaign(
            trigger_alert_id=alert_id,
            source_ip=source_ip,
            hostname=hostname,
            group_id=group_id,
            case_id=existing_case_id,
        ))
        if search_queries:
            asyncio.ensure_future(_run_ai_searches(alert_id, existing_case_id, search_queries))
        return

    # ── 7. Buat case baru ───────────────────────────────────────────────────
    case_id = await _create_case_from_verdict(
        alert_id=alert_id,
        title=title,
        severity=effective_severity,
        verdict=verdict,
        analysis=analysis,
        enrichment=enrichment,
        group_id=group_id,
    )

    if not case_id:
        return

    # ── 8. Campaign analyzer + search results ke case (background) ─────────
    asyncio.ensure_future(analyze_campaign(
        trigger_alert_id=alert_id,
        source_ip=source_ip,
        hostname=hostname,
        group_id=group_id,
        case_id=case_id,
    ))
    if search_queries:
        asyncio.ensure_future(_run_ai_searches(alert_id, case_id, search_queries))

    # ── 9. Webhook notification ─────────────────────────────────────────────
    try:
        await dispatch_case_webhooks(
            case_id=case_id,
            title=f"{'🚨 ESKALASI' if verdict == 'escalate' else '[AI]'} {title}",
            severity=effective_severity,
            description=triage_notes[:500] if triage_notes else "",
            group_id=group_id,
            alert_id=uuid.UUID(alert_id) if alert_id else None,
        )
    except Exception as exc:
        log.warning("case_webhook_dispatch_failed", error=str(exc))
