# worker/worker/correlation_engine.py
"""
Checks correlation rules after every new alert.
Uses Redis sorted sets (ZADD/ZRANGEBYSCORE) for time-windowed counting.
Key format: corr:{rule_id}:{match_value}
Dedup key: corr_fired:{rule_id}:{match_value} — TTL = timewindow seconds.
"""
import time
import uuid
import structlog
from sqlalchemy import select
from worker.database import AsyncSessionLocal
from worker.models import Alert, CorrelationRule
from worker.redis_client import get_redis

log = structlog.get_logger()

_RULES_TTL = 60.0
_rules_cache: list = []
_rules_loaded_at: float = 0.0


async def _get_rules() -> list:
    global _rules_cache, _rules_loaded_at
    if time.monotonic() - _rules_loaded_at > _RULES_TTL:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(CorrelationRule).where(CorrelationRule.is_enabled == True)
            )
            _rules_cache = list(result.scalars().all())
            _rules_loaded_at = time.monotonic()
    return _rules_cache


async def check_correlation(
    alert_id: uuid.UUID,
    source_ip: str | None,
    hostname: str | None,
    group_id: str,
    severity: str,
) -> None:
    rules = await _get_rules()
    if not rules:
        return

    redis = await get_redis()
    now = time.time()

    for rule in rules:
        if rule.group_id and rule.group_id != group_id:
            continue
        if rule.severity_filter and rule.severity_filter != severity:
            continue

        match_value = {
            "source_ip": source_ip,
            "hostname": hostname,
            "group_id": group_id,
        }.get(rule.match_field)
        if not match_value:
            continue

        key = f"corr:{rule.id}:{match_value}"
        window_start = now - rule.timewindow

        await redis.zadd(key, {str(alert_id): now})
        await redis.zremrangebyscore(key, "-inf", window_start)
        await redis.expire(key, rule.timewindow * 2)

        count = await redis.zcard(key)
        if count >= rule.min_count:
            dedup_key = f"corr_fired:{rule.id}:{match_value}"
            fired = await redis.set(dedup_key, "1", nx=True, ex=rule.timewindow)
            if fired is None:
                continue

            title = (
                rule.output_title
                .replace("{count}", str(count))
                .replace("{match_value}", match_value)
            )
            log.info("correlation_triggered", rule_id=str(rule.id), match_value=match_value, count=count)

            try:
                async with AsyncSessionLocal() as db:
                    corr_alert = Alert(
                        title=title,
                        severity=rule.output_severity,
                        status="new",
                        group_id=group_id,
                        source_ip=source_ip if rule.match_field == "source_ip" else None,
                        hostname=hostname if rule.match_field == "hostname" else None,
                    )
                    db.add(corr_alert)
                    await db.commit()
            except Exception as db_exc:
                log.error("correlation_alert_db_failed", rule_id=str(rule.id), error=str(db_exc))
                await redis.delete(dedup_key)
