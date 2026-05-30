# worker/worker/report_sender.py
"""Weekly digest email: summary of alerts in the past 7 days."""
import asyncio
import html
import json
from datetime import datetime, timezone, timedelta
from collections import Counter

import structlog
from sqlalchemy import select, text

from worker.database import AsyncSessionLocal
from worker.models import Alert
from worker.settings_cache import get_setting

log = structlog.get_logger()

REDIS_KEY = "siem:report:last_sent_at"
REPORT_INTERVAL_DAYS = 7
CHECK_INTERVAL = 3600  # check hourly


async def _generate_ai_narrative(alerts: list, cutoff) -> str:
    """Ask Groq to generate an executive summary of the week's security posture."""
    from worker.groq_client import _groq_post
    from worker.settings_cache import get_setting

    api_key = await get_setting("groq_api_key") or ""
    if not api_key:
        return ""

    # Gather AI verdict distribution from cases created in the period
    verdict_dist: dict = {}
    top_mitre: list = []
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    COALESCE(ioc_data->>'verdict', 'unknown') AS verdict,
                    COUNT(*) AS cnt
                FROM cases
                WHERE created_at >= :cutoff
                  AND created_by_ai = TRUE
                GROUP BY COALESCE(ioc_data->>'verdict', 'unknown')
            """), {"cutoff": cutoff})).mappings().all()
            verdict_dist = {r["verdict"]: r["cnt"] for r in rows}

            mitre_rows = (await db.execute(text("""
                SELECT DISTINCT jsonb_array_elements_text(ioc_data->'mitre_techniques') AS technique
                FROM cases
                WHERE created_at >= :cutoff
                  AND created_by_ai = TRUE
                  AND ioc_data ? 'mitre_techniques'
                LIMIT 10
            """), {"cutoff": cutoff})).mappings().all()
            top_mitre = [r["technique"] for r in mitre_rows]
    except Exception as e:
        log.warning("report_narrative_data_failed", error=str(e))

    severity_counts: dict = {}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    prompt = f"""You are an AI SOC analyst writing a weekly executive security report.

Data for this week:
- Total alerts: {len(alerts)}
- Severity breakdown: {json.dumps(severity_counts)}
- AI verdict distribution: {json.dumps(verdict_dist)}
- MITRE ATT&CK techniques observed: {top_mitre}

Write a 3-paragraph executive summary in Indonesian:
1. Overview of the week's threat landscape
2. Key findings (campaigns detected, top techniques, notable patterns)
3. Recommended focus areas for the coming week

Keep it concise — max 200 words total. No bullet points, pure paragraphs."""

    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    try:
        result = await _groq_post(api_key, {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 400,
        })
        return result["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.warning("report_narrative_failed", error=str(exc))
        return ""


async def _send_digest(alerts: list, cutoff) -> None:
    enabled = await get_setting("smtp_enabled", "false")
    if enabled.lower() != "true":
        return

    smtp_host = await get_setting("smtp_host", "")
    if not smtp_host:
        return

    import aiosmtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_port     = int(await get_setting("smtp_port", "587"))
    smtp_user     = await get_setting("smtp_user", "")
    smtp_pass     = await get_setting("smtp_password", "")
    smtp_from     = await get_setting("smtp_from", "") or smtp_user
    smtp_to_raw   = await get_setting("smtp_to", "")
    recipients    = [r.strip() for r in smtp_to_raw.split(",") if r.strip()]
    if not recipients or not smtp_from:
        return

    narrative = await _generate_ai_narrative(alerts, cutoff)
    narrative_html = ""
    if narrative:
        narrative_html = (
            '<div style="background:#0a1628;border-left:3px solid #00d4ff;'
            'padding:16px;margin-bottom:20px;border-radius:4px">'
            '<h3 style="color:#00d4ff;margin:0 0 8px 0;font-size:13px">'
            '🤖 AI SOC Analyst — Weekly Summary</h3>'
            f'<p style="color:#c8d8e8;font-size:13px;line-height:1.6;margin:0">'
            f'{narrative.replace(chr(10), "<br>")}</p>'
            '</div>'
        )

    by_severity = Counter(a.severity for a in alerts)
    total = len(alerts)
    top_rules: list[str] = []
    rule_counts = Counter(a.title for a in alerts)
    for title, count in rule_counts.most_common(5):
        top_rules.append(f"<li>{html.escape(title)} — <b>{count}</b></li>")

    sev_rows = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = by_severity.get(sev, 0)
        if n:
            colors = {"critical": "#E74C3C", "high": "#E67E22", "medium": "#F39C12", "low": "#3498DB", "info": "#95A5A6"}
            c = colors.get(sev, "#aaa")
            sev_rows += f'<tr><td style="padding:6px 12px;border:1px solid #1e293b;color:{c};font-weight:bold;text-transform:uppercase">{sev}</td><td style="padding:6px 12px;border:1px solid #1e293b">{n}</td></tr>'

    body = f"""\
<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:20px">
<div style="max-width:600px;margin:0 auto">
  <h2 style="color:#00d4ff">Weekly SIEM Digest</h2>
  <p style="color:#94a3b8">Period: last 7 days — {total} total alerts</p>
  {narrative_html}<h3 style="color:#94a3b8;font-size:14px">By Severity</h3>
  <table style="width:100%;border-collapse:collapse;margin-bottom:20px">{sev_rows}</table>
  <h3 style="color:#94a3b8;font-size:14px">Top Rules Triggered</h3>
  <ul style="color:#e2e8f0;padding-left:20px">{''.join(top_rules) or '<li>None</li>'}</ul>
</div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[SIEM] Weekly Digest — {total} alerts"
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "html"))

    try:
        use_tls = smtp_port == 465
        await aiosmtplib.send(
            msg, hostname=smtp_host, port=smtp_port,
            start_tls=(not use_tls and smtp_port == 587),
            use_tls=use_tls,
            username=smtp_user or None,
            password=smtp_pass or None,
            timeout=15,
        )
        log.info("weekly_digest_sent", total=total, recipients=len(recipients))
    except Exception as exc:
        log.error("weekly_digest_failed", error=str(exc))


async def report_loop(redis) -> None:
    while True:
        try:
            enabled = await get_setting("smtp_enabled", "false")
            if enabled.lower() == "true":
                last_raw = await redis.get(REDIS_KEY)
                now = datetime.now(timezone.utc)
                should_send = True
                if last_raw:
                    try:
                        last_dt = datetime.fromisoformat(last_raw)
                        should_send = (now - last_dt).days >= REPORT_INTERVAL_DAYS
                    except Exception:
                        pass

                if should_send:
                    cutoff = now - timedelta(days=REPORT_INTERVAL_DAYS)
                    async with AsyncSessionLocal() as db:
                        result = await db.execute(
                            select(Alert).where(Alert.created_at >= cutoff)
                        )
                        alerts = result.scalars().all()
                    await _send_digest(list(alerts), cutoff)
                    await redis.set(REDIS_KEY, now.isoformat())
        except Exception as exc:
            log.error("report_loop_error", error=str(exc))

        await asyncio.sleep(CHECK_INTERVAL)
