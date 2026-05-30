# worker/worker/webhook_sender.py
import asyncio
import math
from datetime import datetime, timezone
import httpx
import structlog
from prometheus_client import Counter
from sqlalchemy import select
from worker.config import MAX_WEBHOOK_ATTEMPTS, WEBHOOK_RETRY_INTERVAL
from worker.database import AsyncSessionLocal
from worker.models import WebhookConfig, WebhookDelivery

log = structlog.get_logger()

webhook_deliveries_total = Counter(
    "siem_webhook_deliveries_total",
    "Webhook delivery attempts by status",
    ["status"],
)

async def webhook_retry_loop() -> None:
    while True:
        await asyncio.sleep(WEBHOOK_RETRY_INTERVAL)
        try:
            await _process_pending_deliveries()
        except Exception as exc:
            log.error("webhook_retry_error", error=str(exc))

async def _process_pending_deliveries() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(WebhookDelivery, WebhookConfig)
            .join(WebhookConfig, WebhookDelivery.webhook_config_id == WebhookConfig.id)
            .where(
                WebhookDelivery.status.notin_(["delivered", "failed"]),
                WebhookDelivery.attempts < MAX_WEBHOOK_ATTEMPTS,
            )
        )
        rows = result.all()

    for delivery, config in rows:
        next_attempt_time = _backoff_time(delivery.attempts)
        if delivery.last_attempted_at:
            elapsed = (datetime.now(timezone.utc) - delivery.last_attempted_at).total_seconds()
            if elapsed < next_attempt_time:
                continue
        await _deliver(delivery, config)

def _build_jira_payload(ctx: dict) -> dict:
    """Build Jira Create Issue API payload from alert context."""
    severity = ctx.get("severity", "medium")
    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
    title = ctx.get("title", "Security Alert")
    source_ip = ctx.get("source_ip", "N/A")
    hostname = ctx.get("hostname", "N/A")
    triage_notes = ctx.get("triage_notes", "Pending AI analysis")
    alert_id = ctx.get("alert_id", "")
    created_at = ctx.get("created_at", "")
    desc = (
        f"Source: {source_ip} / {hostname}\n"
        f"Severity: {severity}\n"
        f"Detected: {created_at}\n\n"
        f"AI Triage Notes:\n{triage_notes}\n\n"
        f"Alert ID: {alert_id}"
    )
    return {
        "fields": {
            "summary": f"[SIEM {severity.upper()}] {title}",
            "description": {
                "version": 1, "type": "doc",
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": desc}]}],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority_map.get(severity, "Medium")},
            "labels": ["siem", f"severity-{severity}", "auto-created"],
        }
    }


def _build_servicenow_payload(ctx: dict) -> dict:
    """Build ServiceNow Create Incident API payload from alert context."""
    severity = ctx.get("severity", "medium")
    urgency_map = {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "4"}
    return {
        "short_description": f"[SIEM] {ctx.get('title', 'Security Alert')}",
        "description": (
            f"Source IP: {ctx.get('source_ip', 'N/A')}\n"
            f"Hostname: {ctx.get('hostname', 'N/A')}\n"
            f"Severity: {severity}\n"
            f"AI Notes: {ctx.get('triage_notes', '')}"
        ),
        "urgency": urgency_map.get(severity, "3"),
        "category": "Security",
        "subcategory": "Intrusion",
        "caller_id": "siem-platform",
    }


_SEVERITY_COLORS = {
    "critical": 0xE74C3C,
    "high":     0xE67E22,
    "medium":   0xF1C40F,
    "low":      0x3498DB,
    "info":     0x95A5A6,
}

def _discord_payload(payload: dict) -> dict:
    severity = payload.get("severity", "medium").lower()
    color = _SEVERITY_COLORS.get(severity, 0x95A5A6)
    event = payload.get("event", "alert")

    if event == "case_created":
        title = f"New AI Case: {payload.get('title', 'Unknown')}"
        desc = payload.get("description", "") or ""
        fields = [
            {"name": "Severity", "value": severity.upper(), "inline": True},
            {"name": "Case ID", "value": payload.get("case_id", "")[:8] + "...", "inline": True},
        ]
    else:
        title = f"Alert: {payload.get('title', 'Unknown')}"
        desc = ""
        fields = [
            {"name": "Severity", "value": severity.upper(), "inline": True},
        ]
        if payload.get("source_ip"):
            fields.append({"name": "Source IP", "value": payload["source_ip"], "inline": True})
        if payload.get("hostname"):
            fields.append({"name": "Hostname", "value": payload["hostname"], "inline": True})

    return {
        "embeds": [{
            "title": title,
            "description": desc[:2000] if desc else None,
            "color": color,
            "fields": fields,
            "timestamp": payload.get("timestamp"),
            "footer": {"text": "SIEM Platform"},
        }]
    }


async def _deliver(delivery: WebhookDelivery, config: WebhookConfig) -> None:
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        try:
            is_discord = "discord.com/api/webhooks" in config.url
            # Select payload format based on webhook config
            fmt = getattr(config, "payload_format", "default") or "default"
            if is_discord:
                post_payload = _discord_payload(delivery.payload)
            elif fmt == "jira":
                post_payload = _build_jira_payload(delivery.payload)
            elif fmt == "servicenow":
                post_payload = _build_servicenow_payload(delivery.payload)
            else:
                post_payload = delivery.payload
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(config.url, json=post_payload)
                resp.raise_for_status()
            status = "delivered"
            webhook_deliveries_total.labels(status="delivered").inc()
            log.info("webhook_delivered", delivery_id=str(delivery.id), url=config.url)
        except Exception as exc:
            new_attempts = delivery.attempts + 1
            status = "failed" if new_attempts >= MAX_WEBHOOK_ATTEMPTS else "pending"
            metric_status = "failed" if status == "failed" else "retry"
            webhook_deliveries_total.labels(status=metric_status).inc()
            log.warning("webhook_failed", delivery_id=str(delivery.id), attempts=new_attempts, error=str(exc))

        from sqlalchemy import update
        await db.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery.id)
            .values(
                status=status,
                attempts=delivery.attempts + 1,
                last_attempted_at=now,
                updated_at=now,
            )
        )
        await db.commit()

def _backoff_time(attempts: int) -> float:
    return min((attempts ** 2) * 30, 3600)
