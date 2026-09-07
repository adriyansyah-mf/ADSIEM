# worker/worker/alert_manager.py
import json
import uuid
import structlog
from datetime import datetime, timezone
from sqlalchemy import select, text
from worker.database import AsyncSessionLocal
from worker.redis_client import get_redis
from worker.config import AI_ANALYSIS_QUEUE
from worker.ai_queue import mark_queued
from worker.soar_engine import run_soar_playbooks
from worker.email_sender import send_alert_email
from worker.settings_cache import get_setting

log = structlog.get_logger()

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


async def _choose_least_loaded_analyst(group_id: str) -> uuid.UUID | None:
    """Return the active analyst with the fewest open alerts when auto-assign is enabled."""
    if (await get_setting("auto_assign_alerts", "false")).lower() != "true":
        return None
    async with AsyncSessionLocal() as db:
        result = await db.execute(text(
            "SELECT u.id FROM users u "
            "LEFT JOIN alerts a ON a.assignee_id = u.id AND a.status IN ('new', 'in_progress') "
            "WHERE u.is_active = TRUE AND u.group_id = :group_id "
            "GROUP BY u.id ORDER BY COUNT(a.id), u.id LIMIT 1"
        ), {"group_id": group_id})
        row = result.first()
    return uuid.UUID(str(row[0])) if row else None


def _severity_gte(sev: str, minimum: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) >= _SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


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


async def _should_ai_investigate(severity: str) -> bool:
    min_sev = await get_setting("ai_min_severity", "high")
    return _severity_gte(severity, min_sev)


async def _is_suppressed(
    group_id: str, source_ip: str | None, hostname: str | None,
    user: str | None, rule_title: str,
) -> bool:
    from worker.models import AlertSuppression
    checks = []
    if source_ip:
        checks.append(("ip", source_ip))
    if hostname:
        checks.append(("hostname", hostname))
    if user:
        checks.append(("user", user))
    checks.append(("rule_title", rule_title))

    async with AsyncSessionLocal() as db:
        for etype, evalue in checks:
            from sqlalchemy import or_
            row = (await db.execute(
                select(AlertSuppression).where(
                    AlertSuppression.is_active,
                    AlertSuppression.entity_type == etype,
                    AlertSuppression.entity_value == evalue,
                    or_(AlertSuppression.group_id == group_id,
                        AlertSuppression.group_id == "default"),
                )
            )).scalar_one_or_none()
            if row:
                log.info("alert_suppressed", entity_type=etype, entity_value=evalue,
                         rule=rule_title, reason=row.reason)
                return True
    return False


async def create_alert(
    rule_match: dict,
    event_id: uuid.UUID | None,
    agent_id: uuid.UUID | None,
    group_id: str,
    source_ip: str | None,
    hostname: str | None,
    user: str | None = None,
) -> uuid.UUID | None:
    from worker.models import Alert, WebhookConfig, WebhookDelivery

    if await _is_suppressed(group_id, source_ip, hostname, user, rule_match["title"]):
        return None

    # Deduplication: bump duplicate_count on existing open alert instead of creating new one
    from datetime import timedelta
    dedup_window = datetime.now(timezone.utc) - timedelta(minutes=30)
    async with AsyncSessionLocal() as db:
        dedup_q = (
            select(Alert)
            .where(Alert.title == rule_match["title"])
            .where(Alert.group_id == group_id)
            .where(Alert.status.in_(["new", "in_progress"]))
            .where(Alert.created_at >= dedup_window)
        )
        if rule_match.get("correlation_key"):
            dedup_q = dedup_q.where(Alert.correlation_key == rule_match["correlation_key"])
        if source_ip:
            dedup_q = dedup_q.where(Alert.source_ip == source_ip)
        elif hostname:
            dedup_q = dedup_q.where(Alert.hostname == hostname)
        existing = (await db.execute(dedup_q.limit(1))).scalar_one_or_none()
        if existing:
            existing.duplicate_count = (existing.duplicate_count or 0) + 1
            await db.commit()
            log.info("alert_deduplicated", title=rule_match["title"],
                     existing_id=str(existing.id), count=existing.duplicate_count)
            return existing.id

    async with AsyncSessionLocal() as db:
        try:
            originating_rule_id = uuid.UUID(str(rule_match.get("id")))
        except (TypeError, ValueError, AttributeError):
            originating_rule_id = None
        assignee_id = await _choose_least_loaded_analyst(group_id)
        alert = Alert(
            title=rule_match["title"],
            severity=rule_match["level"],
            status="new",
            rule_id=originating_rule_id,
            correlation_id=rule_match.get("correlation_id"),
            correlation_key=rule_match.get("correlation_key"),
            source_event_ids=rule_match.get("source_event_ids", []),
            event_id=event_id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=source_ip,
            hostname=hostname,
            assignee_id=assignee_id,
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
                WebhookConfig.is_enabled,
                (WebhookConfig.group_id.is_(None)) | (WebhookConfig.group_id == group_id)
            )
        )
        webhooks = result.scalars().all()
        for webhook in webhooks:
            db.add(WebhookDelivery(
                alert_id=alert_id,
                webhook_config_id=webhook.id,
                group_id=group_id,
                payload=payload,
                status="pending",
                attempts=0,
            ))

        await db.commit()

    # Publish to Redis for WebSocket broadcast (best-effort)
    try:
        redis = await get_redis()
        await redis.publish("ws:alerts", json.dumps({
            "type": "new_alert",
            "id": str(alert_id),
            "title": rule_match["title"],
            "severity": rule_match["level"],
            "source_ip": source_ip,
            "hostname": hostname,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception:
        pass

    # Push to AI analysis queue — gated by the configurable ai_min_severity setting
    try:
        redis = await get_redis()
        risk = await _get_entity_risk_max(source_ip, hostname)
        if await _should_ai_investigate(rule_match["level"]):
            await mark_queued(redis, str(alert_id))
            await redis.rpush(AI_ANALYSIS_QUEUE, json.dumps({
                "alert_id": str(alert_id),
                "title": rule_match["title"],
                "severity": rule_match["level"],
                "source_ip": source_ip,
                "hostname": hostname,
                "decoded_fields": rule_match.get("matched_fields", {}),
                "sigma_rule": rule_match.get("sigma_rule", {}),
                "group_id": group_id,
            }))
            log.info("ai_queued", alert_id=str(alert_id),
                     severity=rule_match["level"], entity_risk=round(risk, 2))
        else:
            log.info("ai_gate_blocked", alert_id=str(alert_id),
                     severity=rule_match["level"], entity_risk=round(risk, 2))
    except Exception as exc:
        log.error("ai_queue_push_failed", alert_id=str(alert_id), error=str(exc))

    try:
        await run_soar_playbooks(
            alert_id=alert_id,
            rule_match=rule_match,
            source_ip=source_ip,
            hostname=hostname,
            user_name=user,
            group_id=group_id,
        )
    except Exception as exc:
        log.error("soar_dispatch_failed", error=str(exc))

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
                WebhookConfig.is_enabled,
                (WebhookConfig.group_id.is_(None)) | (WebhookConfig.group_id == group_id)
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
                group_id=group_id,
                payload=payload,
                status="pending",
                attempts=0,
            ))
        await db.commit()
