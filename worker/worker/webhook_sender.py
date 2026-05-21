# worker/worker/webhook_sender.py
import asyncio
import math
from datetime import datetime, timezone
import httpx
import structlog
from sqlalchemy import select
from worker.config import MAX_WEBHOOK_ATTEMPTS, WEBHOOK_RETRY_INTERVAL
from worker.database import AsyncSessionLocal
from worker.models import WebhookConfig, WebhookDelivery

log = structlog.get_logger()

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

async def _deliver(delivery: WebhookDelivery, config: WebhookConfig) -> None:
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(config.url, json=delivery.payload)
                resp.raise_for_status()
            status = "delivered"
            log.info("webhook_delivered", delivery_id=str(delivery.id), url=config.url)
        except Exception as exc:
            new_attempts = delivery.attempts + 1
            status = "failed" if new_attempts >= MAX_WEBHOOK_ATTEMPTS else "pending"
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
