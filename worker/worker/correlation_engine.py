"""Check whether a new alert triggers any correlation rules and fire a correlated alert."""
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, func

from worker.database import AsyncSessionLocal
from worker.models import Alert, CorrelationRule

log = structlog.get_logger()


async def check_correlation(
    alert_id: str,
    source_ip: Optional[str],
    hostname: Optional[str],
    group_id: str,
    severity: str,
) -> None:
    async with AsyncSessionLocal() as db:
        q = select(CorrelationRule).where(
            CorrelationRule.is_enabled == True,
        )
        rules = (await db.execute(q)).scalars().all()

        for rule in rules:
            # Apply group filter if rule has one
            if rule.group_id and rule.group_id != group_id:
                continue

            # Apply severity filter if set
            if rule.severity_filter and rule.severity_filter != severity:
                continue

            # Determine the match value from the alert being created
            if rule.match_field == "source_ip":
                match_value = source_ip
            elif rule.match_field == "hostname":
                match_value = hostname
            else:
                continue

            if not match_value:
                continue

            # Count recent alerts matching this field/value within the time window
            window_start = datetime.now(timezone.utc) - timedelta(seconds=rule.timewindow)
            count_q = select(func.count()).select_from(Alert).where(
                Alert.group_id == group_id,
                Alert.created_at >= window_start,
            )
            if rule.match_field == "source_ip":
                count_q = count_q.where(Alert.source_ip == match_value)
            elif rule.match_field == "hostname":
                count_q = count_q.where(Alert.hostname == match_value)

            count = (await db.execute(count_q)).scalar() or 0

            if count >= rule.min_count:
                title = rule.output_title.format(count=count, match_value=match_value)
                # Avoid duplicate correlated alerts: check one doesn't already exist
                existing_q = select(Alert).where(
                    Alert.title == title,
                    Alert.group_id == group_id,
                    Alert.created_at >= window_start,
                ).limit(1)
                existing = (await db.execute(existing_q)).scalar_one_or_none()
                if existing:
                    continue

                correlated = Alert(
                    title=title,
                    severity=rule.output_severity,
                    status="new",
                    source_ip=match_value if rule.match_field == "source_ip" else None,
                    hostname=match_value if rule.match_field == "hostname" else None,
                    group_id=group_id,
                    rule_title=f"[Correlation] {rule.title}",
                    raw_log=f"Correlated: {count} alerts from {match_value} in {rule.timewindow}s",
                )
                db.add(correlated)
                log.info("correlation_fired", rule=rule.title, match_value=match_value, count=count)

        await db.commit()
