"""Send email notification for a single alert (if SMTP is configured and severity qualifies)."""
import smtplib
import ssl
from email.mime.text import MIMEText
from typing import Optional

import structlog

from worker.settings_cache import get_setting

log = structlog.get_logger()

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_gte(sev: str, minimum: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) >= _SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


async def send_alert_email(
    title: str,
    severity: str,
    source_ip: Optional[str] = None,
    hostname: Optional[str] = None,
) -> None:
    enabled = await get_setting("smtp_enabled", "false")
    if enabled.lower() != "true":
        return

    min_sev = await get_setting("smtp_min_severity", "high")
    if not _severity_gte(severity, min_sev):
        return

    smtp_host = await get_setting("smtp_host", "")
    smtp_port = int(await get_setting("smtp_port", "587"))
    smtp_user = await get_setting("smtp_user", "")
    smtp_pass = await get_setting("smtp_password", "")
    smtp_from = await get_setting("smtp_from", "") or smtp_user
    smtp_to_raw = await get_setting("smtp_to", "")

    if not smtp_host or not smtp_to_raw:
        return

    recipients = [r.strip() for r in smtp_to_raw.split(",") if r.strip()]
    if not recipients:
        return

    body = f"SIEM Alert: {title}\nSeverity: {severity}\n"
    if source_ip:
        body += f"Source IP: {source_ip}\n"
    if hostname:
        body += f"Hostname: {hostname}\n"

    msg = MIMEText(body)
    msg["Subject"] = f"[SIEM] [{severity.upper()}] {title}"
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)

    try:
        if smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as s:
                if smtp_user:
                    s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_from, recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as s:
                s.ehlo()
                if smtp_port == 587:
                    s.starttls()
                if smtp_user:
                    s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_from, recipients, msg.as_string())
        log.info("alert_email_sent", title=title, severity=severity, recipients=recipients)
    except Exception as exc:
        log.error("alert_email_failed", error=str(exc))
