# worker/worker/alert_manager.py
import json
import uuid
import structlog
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from worker.database import AsyncSessionLocal
from worker.redis_client import get_redis
from worker.config import AI_ANALYSIS_QUEUE
from worker.ai_queue import mark_queued
from worker.correlation_engine import check_correlation
from worker.email_sender import send_alert_email

log = structlog.get_logger()


async def _get_entity_risk_max(source_ip: str | None, hostname: str | None) -> float:
    """Return the max UEBA risk score between the IP and hostname entities."""
    from worker.models import UebaEntityScore
    scores = []
    async with AsyncSessionLocal() as db:
        if source_ip:
            row = await db.get(UebaEntityScore, ("ip", source_ip))
            if row:
                scores.append(row.risk_score)
        if hostname:
            row = await db.get(UebaEntityScore, ("host", hostname))
            if row:
                scores.append(row.risk_score)
    return max(scores) if scores else 0.0


def _should_ai_investigate(risk: float, severity: str) -> bool:
    if severity == "critical":
        return True
    if risk >= 60:
        return True
    if severity == "high" and risk >= 40:
        return True
    return False


async def create_alert(
    rule_match: dict,
    event_id: uuid.UUID | None,
    agent_id: uuid.UUID | None,
    group_id: str,
    source_ip: str | None,
    hostname: str | None,
) -> uuid.UUID:
    from worker.models import Alert, WebhookConfig, WebhookDelivery

    async with AsyncSessionLocal() as db:
        alert = Alert(
            title=rule_match["title"],
            severity=rule_match["level"],
            status="new",
            rule_id=None,
            event_id=event_id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=source_ip,
            hostname=hostname,
        )
        db.add(alert)
        await db.flush()

        # capture id before commit so it's safe to use after session closes
        alert_id: uuid.UUID = alert.id

        payload = {
            "alert_id": str(alert_id),
            "title": rule_match["title"],
            "severity": rule_match["level"],
            "source_ip": source_ip,
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        result = await db.execute(
            select(WebhookConfig).where(
                WebhookConfig.is_enabled == True,
                (WebhookConfig.group_id == None) | (WebhookConfig.group_id == group_id)
            )
        )
        webhooks = result.scalars().all()
        for webhook in webhooks:
            db.add(WebhookDelivery(
                alert_id=alert_id,
                webhook_config_id=webhook.id,
                payload=payload,
                status="pending",
                attempts=0,
            ))

        await db.commit()

    # Push to AI analysis queue — gated by ML entity risk score
    try:
        redis = await get_redis()
        risk = await _get_entity_risk_max(source_ip, hostname)
        if _should_ai_investigate(risk, rule_match["level"]):
            await mark_queued(redis, str(alert_id))
            await redis.rpush(AI_ANALYSIS_QUEUE, json.dumps({
                "alert_id": str(alert_id),
                "title": rule_match["title"],
                "severity": rule_match["level"],
                "source_ip": source_ip,
                "hostname": hostname,
                "decoded_fields": rule_match.get("matched_fields", {}),
                "group_id": group_id,
            }))
        else:
            log.debug("ai_gate_blocked", alert_id=str(alert_id),
                      severity=rule_match["level"], entity_risk=risk)
    except Exception as exc:
        log.error("ai_queue_push_failed", alert_id=str(alert_id), error=str(exc))

    try:
        await check_correlation(
            alert_id=alert_id,
            source_ip=source_ip,
            hostname=hostname,
            group_id=group_id,
            severity=rule_match["level"],
        )
    except Exception as exc:
        log.error("correlation_check_failed", error=str(exc))

    try:
        await send_alert_email(
            title=rule_match["title"],
            severity=rule_match["level"],
            source_ip=source_ip,
            hostname=hostname,
        )
    except Exception as exc:
        log.error("email_dispatch_failed", error=str(exc))

    return alert_id


async def dispatch_case_webhooks(
    case_id: str,
    title: str,
    severity: str,
    description: str,
    group_id: str,
    alert_id: uuid.UUID | None,
) -> None:
    """Queue webhook deliveries for an AI-created case."""
    if not alert_id:
        return
    from worker.models import WebhookConfig, WebhookDelivery
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(WebhookConfig).where(
                WebhookConfig.is_enabled == True,
                (WebhookConfig.group_id == None) | (WebhookConfig.group_id == group_id)
            )
        )
        webhooks = result.scalars().all()
        if not webhooks:
            return
        payload = {
            "event": "case_created",
            "case_id": case_id,
            "title": title,
            "severity": severity,
            "description": description[:500] if description else "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": str(alert_id),
        }
        for webhook in webhooks:
            db.add(WebhookDelivery(
                alert_id=alert_id,
                webhook_config_id=webhook.id,
                payload=payload,
                status="pending",
                attempts=0,
            ))
        await db.commit()
