# worker/worker/campaign_analyzer.py
"""
Campaign Analyzer — melihat gambaran besar serangan.

Setelah sebuah case dibuat oleh AI, fungsi ini mengumpulkan SEMUA alert
dari IP/host yang sama dalam 24 jam terakhir,
lalu meminta Groq membangun timeline dan narasi kampanye serangan secara utuh.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, or_

from worker.database import AsyncSessionLocal
from worker.models import Alert, CaseNote
from worker.llm_client import analyze_campaign_with_ai

log = structlog.get_logger()

LOOKBACK_HOURS = 24
MIN_RELATED_ALERTS = 2   # jangan analisis kampanye jika cuma 1 alert


async def analyze_campaign(
    trigger_alert_id: str,
    source_ip: Optional[str],
    hostname: Optional[str],
    group_id: str,
    case_id: str,
) -> None:
    """
    Entry point. Dipanggil sebagai fire-and-forget task setelah case dibuat.
    Jika tidak ada cukup related alerts, langsung return — tidak membuang token.
    """
    try:
        await _run(trigger_alert_id, source_ip, hostname, group_id, case_id)
    except Exception as exc:
        log.error("campaign_analyzer_failed", case_id=case_id, error=str(exc))


async def _run(
    trigger_alert_id: str,
    source_ip: Optional[str],
    hostname: Optional[str],
    group_id: str,
    case_id: str,
) -> None:
    window_start = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    async with AsyncSessionLocal() as db:
        # Kumpulkan semua alert yang berhubungan (IP atau hostname sama)
        filters = []
        if source_ip:
            filters.append(Alert.source_ip == source_ip)
        if hostname:
            filters.append(Alert.hostname == hostname)

        if not filters:
            return

        alerts_q = (
            select(Alert)
            .where(
                Alert.group_id == group_id,
                Alert.created_at >= window_start,
                or_(*filters),
            )
            .order_by(Alert.created_at.asc())
            .limit(100)
        )
        alerts = (await db.execute(alerts_q)).scalars().all()

        if len(alerts) < MIN_RELATED_ALERTS:
            log.debug("campaign_skip_too_few", count=len(alerts), case_id=case_id)
            return

        # UEBA anomalies are deliberately NOT gathered here. UEBA output is not
        # fed to the AI and does not reach cases: its scores are advisory signals
        # for an analyst to read on the UEBA page, not evidence for a model to
        # narrate. Campaign analysis correlates alerts only.

        # Bangun timeline string untuk dikirim ke Groq
        timeline = _build_timeline(alerts)

        log.info("campaign_analyzing",
                 case_id=case_id,
                 alert_count=len(alerts),
                 source_ip=source_ip,
                 hostname=hostname)

        analysis = await analyze_campaign_with_ai(
            source_ip=source_ip,
            hostname=hostname,
            timeline=timeline,
            alert_count=len(alerts),
        )

        if not analysis:
            return

        # Simpan hasil analisis sebagai CaseNote di case yang sudah ada
        narrative = _format_note(analysis, alerts, source_ip, hostname)
        note = CaseNote(
            case_id=uuid.UUID(case_id),
            author_id=None,
            content=narrative,
            is_ai_generated=True,
        )
        db.add(note)
        await db.commit()
        log.info("campaign_note_saved", case_id=case_id)


def _build_timeline(alerts: list) -> str:
    """Buat string timeline yang terurut dari alert saja (UEBA tidak disertakan)."""
    events = []

    for a in alerts:
        ts = a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if a.created_at else "?"
        dup = f" (x{a.duplicate_count + 1})" if a.duplicate_count else ""
        events.append((
            a.created_at,
            f"[{ts}] ALERT [{a.severity.upper()}]{dup} — {a.title}"
            + (f" | src={a.source_ip}" if a.source_ip else "")
            + (f" | host={a.hostname}" if a.hostname else "")
        ))

    events.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc))
    return "\n".join(e[1] for e in events)


def _format_note(
    analysis: dict,
    alerts: list,
    source_ip: Optional[str],
    hostname: Optional[str],
) -> str:
    entity = source_ip or hostname or "unknown"
    kill_chain = analysis.get("kill_chain_stage", "Unknown")
    intent = analysis.get("attacker_intent", "-")
    narrative = analysis.get("narrative", "-")
    mitre = analysis.get("mitre_techniques", [])
    recommended = analysis.get("recommended_actions", [])
    confidence = analysis.get("confidence", 0)

    lines = [
        "## 🔍 AI Campaign Analysis",
        "",
        f"**Entity:** `{entity}`  |  **Alerts analyzed:** {len(alerts)}  |  "
        f"**Confidence:** {confidence:.0%}",
        "",
        f"**Kill Chain Stage:** {kill_chain}",
        f"**Attacker Intent:** {intent}",
        "",
        "### Narrative",
        narrative,
    ]

    if mitre:
        lines += ["", "### MITRE ATT&CK Techniques"]
        for t in mitre:
            lines.append(f"- {t}")

    if recommended:
        lines += ["", "### Recommended Actions"]
        for r in recommended:
            lines.append(f"- {r}")

    return "\n".join(lines)
