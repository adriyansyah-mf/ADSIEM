# worker/worker/alert_manager.py
import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from worker.database import AsyncSessionLocal

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

        payload = {
            "alert_id": str(alert.id),
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
                alert_id=alert.id,
                webhook_config_id=webhook.id,
                payload=payload,
                status="pending",
                attempts=0,
            ))

        await db.commit()
        return alert.id
