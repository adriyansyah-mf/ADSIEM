# worker/worker/sla_escalation.py
"""Tenant-configurable SLA escalation: periodically checks open alerts against
their (possibly tenant-overridden) warn/breach thresholds and emits a
one-time-per-threshold notification via the existing email and webhook
delivery pipelines (including the webhook DLQ/retry infrastructure)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.email_sender import send_alert_email
from worker.models import Alert, SlaNotification, SlaPolicy, WebhookConfig, WebhookDelivery

log = structlog.get_logger()

_RESOLVED_STATUSES = {"resolved", "closed", "false_positive"}

# Mirrors server-api's app/api/routes/sla_policies.py defaults -- kept as the
# single source of truth for what "no override configured" means.
DEFAULT_WARN_MINUTES = {"critical": 10, "high": 45, "medium": 180, "low": 1080, "info": 2160}
DEFAULT_BREACH_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440, "info": 2880}

SLA_ESCALATION_INTERVAL = 60  # seconds

# A backlog of pre-existing open alerts (e.g. on first deploy of this feature
# against a database that already has many old open alerts) would otherwise
# all become "newly due" in the same cycle and fire every notification at
# once. Capping per cycle spreads a large backlog across multiple cycles
# instead of bursting -- every overdue alert still eventually gets notified,
# just not all in the same instant.
MAX_ESCALATIONS_PER_CYCLE = 25


def due_thresholds(
    alert_age_minutes: float, warn_minutes: int, breach_minutes: int, already_notified: set[str]
) -> list[str]:
    """Pure function: which thresholds ('warn', 'breach') are newly crossed
    for an alert of this age, given what has already been notified. Kept
    separate from all I/O so the escalation logic itself is unit-testable
    without a database or event loop."""
    due = []
    if alert_age_minutes >= warn_minutes and "warn" not in already_notified:
        due.append("warn")
    if alert_age_minutes >= breach_minutes and "breach" not in already_notified:
        due.append("breach")
    return due


async def sla_escalation_loop() -> None:
    while True:
        await asyncio.sleep(SLA_ESCALATION_INTERVAL)
        try:
            await _check_sla_escalations()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("sla_escalation_error", error=str(exc))


async def _check_sla_escalations() -> None:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        open_alerts = (
            await db.execute(select(Alert).where(Alert.status.notin_(_RESOLVED_STATUSES)))
        ).scalars().all()
        if not open_alerts:
            return

        policies = (await db.execute(select(SlaPolicy))).scalars().all()
        policy_map = {(p.group_id, p.severity): p for p in policies}

        alert_ids = [a.id for a in open_alerts]
        notifications = (
            await db.execute(select(SlaNotification).where(SlaNotification.alert_id.in_(alert_ids)))
        ).scalars().all()
        notified_map: dict = {}
        for n in notifications:
            notified_map.setdefault(n.alert_id, set()).add(n.threshold)

        due: list[tuple] = []
        for alert in sorted(open_alerts, key=lambda a: a.created_at):
            policy = policy_map.get((alert.group_id, alert.severity))
            warn_minutes = policy.warn_minutes if policy else DEFAULT_WARN_MINUTES.get(alert.severity, 180)
            breach_minutes = policy.breach_minutes if policy else DEFAULT_BREACH_MINUTES.get(alert.severity, 240)
            age_minutes = (now - alert.created_at).total_seconds() / 60
            already = notified_map.get(alert.id, set())
            for threshold in due_thresholds(age_minutes, warn_minutes, breach_minutes, already):
                due.append((alert, threshold))

        if len(due) > MAX_ESCALATIONS_PER_CYCLE:
            log.warning(
                "sla_escalation_backlog_capped",
                due_count=len(due), processing=MAX_ESCALATIONS_PER_CYCLE,
            )
        for alert, threshold in due[:MAX_ESCALATIONS_PER_CYCLE]:
            await _emit_escalation(db, alert, threshold, now)


async def _emit_escalation(db, alert: Alert, threshold: str, now: datetime) -> None:
    db.add(SlaNotification(alert_id=alert.id, threshold=threshold, notified_at=now))
    try:
        await db.commit()
    except Exception:
        # Unique(alert_id, threshold) race: another replica already recorded
        # this notification between our SELECT and this INSERT -- skip rather
        # than double-notify.
        await db.rollback()
        return

    try:
        await send_alert_email(
            title=f"SLA {threshold.upper()}: {alert.title}",
            severity=alert.severity,
            source_ip=alert.source_ip,
            hostname=alert.hostname,
        )
    except Exception as exc:
        log.error("sla_escalation_email_failed", alert_id=str(alert.id), error=str(exc))

    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.is_enabled,
            (WebhookConfig.group_id.is_(None)) | (WebhookConfig.group_id == alert.group_id),
        )
    )
    webhooks = result.scalars().all()
    if webhooks:
        payload = {
            "event": f"sla_{threshold}",
            "alert_id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "timestamp": now.isoformat(),
        }
        for webhook in webhooks:
            db.add(WebhookDelivery(
                alert_id=alert.id,
                webhook_config_id=webhook.id,
                group_id=alert.group_id,
                payload=payload,
                status="pending",
                attempts=0,
            ))
        await db.commit()

    log.info("sla_escalation_emitted", alert_id=str(alert.id), threshold=threshold, severity=alert.severity)
