# worker/worker/email_sender.py
"""
Sends HTML email alerts via SMTP.
Reads SMTP config from platform_settings (cached 60s).
Silently skips if smtp_enabled != "true" or smtp_host is empty.
"""
import ssl
import structlog
from datetime import datetime, timezone
from worker.settings_cache import get_setting

log = structlog.get_logger()

_SEVERITY_COLORS = {
    "critical": "#E74C3C",
    "high":     "#E67E22",
    "medium":   "#F39C12",
    "low":      "#3498DB",
    "info":     "#95A5A6",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:20px">
  <div style="max-width:600px;margin:0 auto">
    <h2 style="color:{color};margin-bottom:4px">⚠ SIEM Alert: {title}</h2>
    <p style="color:#94a3b8;font-size:13px;margin:0">{timestamp}</p>
    <table style="width:100%;margin-top:16px;border-collapse:collapse">
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8;width:140px">Severity</td>
          <td style="padding:8px;border:1px solid #1e293b;color:{color};font-weight:bold">{severity}</td></tr>
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8">Source IP</td>
          <td style="padding:8px;border:1px solid #1e293b">{source_ip}</td></tr>
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8">Hostname</td>
          <td style="padding:8px;border:1px solid #1e293b">{hostname}</td></tr>
    </table>
  </div>
</body>
</html>
"""


async def send_alert_email(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
) -> None:
    enabled = await get_setting("smtp_enabled", "false")
    if enabled.lower() != "true":
        return

    smtp_host = await get_setting("smtp_host", "")
    if not smtp_host:
        return

    import aiosmtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_port = int(await get_setting("smtp_port", "587"))
    smtp_user = await get_setting("smtp_user", "")
    smtp_pass = await get_setting("smtp_password", "")
    smtp_from = await get_setting("smtp_from", smtp_user)
    smtp_to_raw = await get_setting("smtp_to", "")
    min_severity = await get_setting("smtp_min_severity", "high")

    _severity_order = ["info", "low", "medium", "high", "critical"]
    if _severity_order.index(severity) < _severity_order.index(min_severity):
        return

    recipients = [r.strip() for r in smtp_to_raw.split(",") if r.strip()]
    if not recipients:
        return

    color = _SEVERITY_COLORS.get(severity, "#95A5A6")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = _HTML_TEMPLATE.format(
        title=title, severity=severity.upper(), color=color,
        source_ip=source_ip or "—", hostname=hostname or "—", timestamp=ts,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[SIEM] {severity.upper()}: {title}"
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        use_tls = smtp_port == 465
        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            start_tls=(not use_tls and smtp_port == 587),
            use_tls=use_tls,
            username=smtp_user or None,
            password=smtp_pass or None,
            timeout=15,
        )
        log.info("email_sent", title=title, severity=severity, recipients=len(recipients))
    except Exception as exc:
        log.warning("email_send_failed", error=str(exc))
