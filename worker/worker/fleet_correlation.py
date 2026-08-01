# worker/worker/fleet_correlation.py
"""Check whether an alert's pattern is isolated to one host or spread across
the fleet — same rule/title firing on other agents in the same window points
to a coordinated or automated campaign rather than a one-off incident."""
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, func

from worker.database import AsyncSessionLocal
from worker.models import Alert

log = structlog.get_logger()

LOOKBACK_HOURS = 24
MAX_HOSTNAMES_LISTED = 15


async def check_fleet_spread(
    title: str,
    group_id: str,
    exclude_hostname: Optional[str],
) -> Optional[dict]:
    """Return {"host_count": N, "hostnames": [...]} for OTHER hosts hit by an
    alert with the same title in the last 24h, or None if none found."""
    window_start = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    async with AsyncSessionLocal() as db:
        q = (
            select(Alert.hostname, func.min(Alert.created_at).label("first_seen"))
            .where(
                Alert.group_id == group_id,
                Alert.title == title,
                Alert.created_at >= window_start,
                Alert.hostname.isnot(None),
            )
            .group_by(Alert.hostname)
        )
        if exclude_hostname:
            q = q.where(Alert.hostname != exclude_hostname)
        rows = (await db.execute(q.order_by(func.min(Alert.created_at).asc()))).all()

    if not rows:
        return None
    return {
        "host_count": len(rows),
        "hostnames": [r.hostname for r in rows[:MAX_HOSTNAMES_LISTED]],
    }
