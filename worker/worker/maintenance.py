# worker/worker/maintenance.py
"""Data retention: purge old logs (Elasticsearch) and closed alerts
(Postgres) on a daily schedule, per tenant. A tenant may override the
platform-wide default retention (and set a document-count storage quota)
via `retention_policies`; a tenant with no row uses the platform default."""
import asyncio
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import delete, select

from worker.database import AsyncSessionLocal
from worker.models import Alert, RetentionPolicy
from worker.settings_cache import get_setting
from worker.es_client import (
    delete_by_query as es_delete_by_query,
    distinct_group_ids,
    find_quota_cutoff,
)

log = structlog.get_logger()

RUN_INTERVAL = 86400  # once per day


def effective_policy(
    policy: RetentionPolicy | None,
    *,
    global_log_days: int,
    global_alert_days: int,
) -> tuple[int, int, int | None]:
    """Resolve a tenant's effective (log_days, alert_days, quota_docs).
    A NULL column on the tenant's override row means "use the platform
    default" for that column specifically, not "no policy" -- a tenant can
    override just one of the three settings and inherit the rest."""
    if policy is None:
        return global_log_days, global_alert_days, None
    log_days = policy.log_retention_days if policy.log_retention_days is not None else global_log_days
    alert_days = policy.alert_retention_days if policy.alert_retention_days is not None else global_alert_days
    return log_days, alert_days, policy.storage_quota_docs


async def _purge_tenant_logs(group_id: str, days: int) -> int:
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return await es_delete_by_query({
        "bool": {"filter": [
            {"term": {"group_id": group_id}},
            {"range": {"created_at": {"lt": cutoff.isoformat()}}},
        ]}
    })


async def _purge_tenant_alerts(db, group_id: str, days: int) -> int:
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        delete(Alert)
        .where(Alert.group_id == group_id)
        .where(Alert.status.in_(["closed", "resolved"]))
        .where(Alert.created_at < cutoff)
    )
    return result.rowcount or 0


async def _enforce_tenant_quota(group_id: str, quota_docs: int | None) -> int:
    if not quota_docs or quota_docs <= 0:
        return 0
    cutoff = await find_quota_cutoff(group_id, quota_docs)
    if cutoff is None:
        return 0
    return await es_delete_by_query({
        "bool": {"filter": [
            {"term": {"group_id": group_id}},
            {"range": {"created_at": {"lte": cutoff}}},
        ]}
    })


async def _all_tenants(db) -> set[str]:
    """Every tenant with data worth considering: anything with a log
    document, an alert, or a configured retention policy. A tenant with a
    policy but no data yet still gets discovered so misconfiguration is
    visible rather than silently never running."""
    from_logs = set(await distinct_group_ids())
    from_alerts = set(
        (await db.execute(select(Alert.group_id).distinct())).scalars().all()
    )
    from_policies = set(
        (await db.execute(select(RetentionPolicy.group_id))).scalars().all()
    )
    return from_logs | from_alerts | from_policies


async def maintenance_loop() -> None:
    await asyncio.sleep(300)  # wait 5 min after startup before first run
    while True:
        try:
            global_log_days = max(
                int(await get_setting("retention_raw_logs_days", "30")),
                int(await get_setting("retention_events_days", "90")),
            )
            global_alert_days = int(await get_setting("retention_alerts_days", "180"))

            async with AsyncSessionLocal() as db:
                tenants = await _all_tenants(db)
                policies = {
                    p.group_id: p
                    for p in (await db.execute(select(RetentionPolicy))).scalars().all()
                }

                total_logs_deleted = 0
                total_alerts_deleted = 0
                total_quota_deleted = 0
                for group_id in tenants:
                    log_days, alert_days, quota_docs = effective_policy(
                        policies.get(group_id),
                        global_log_days=global_log_days,
                        global_alert_days=global_alert_days,
                    )
                    total_logs_deleted += await _purge_tenant_logs(group_id, log_days)
                    total_alerts_deleted += await _purge_tenant_alerts(db, group_id, alert_days)
                    total_quota_deleted += await _enforce_tenant_quota(group_id, quota_docs)

                await db.commit()

            log.info(
                "maintenance_done",
                tenants=len(tenants),
                logs_deleted=total_logs_deleted,
                alerts_deleted=total_alerts_deleted,
                quota_trimmed=total_quota_deleted,
            )
        except Exception as exc:
            log.error("maintenance_error", error=str(exc))

        await asyncio.sleep(RUN_INTERVAL)
