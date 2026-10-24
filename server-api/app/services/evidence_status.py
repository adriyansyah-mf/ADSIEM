"""The operator-facing state of an agent's durable evidence delivery."""
from datetime import datetime, timedelta

from app.core.config import settings

# A queue older than this, or one the sender is retrying, is a backlog.
BACKLOG_AGE = timedelta(minutes=5)


def evidence_status(health: dict | None, reported_at: datetime | None, now: datetime) -> dict:
    """healthy / backlogged / blocked / degraded / not_reported, plus staleness.

    An online heartbeat alone never means evidence delivery is healthy: agents
    that do not report (legacy mode) are not_reported. A stale report keeps its
    last known status and says it is stale."""
    if not health or reported_at is None:
        return {"status": "not_reported", "reason": None, "reported_at": None, "stale": False}
    stale = now - reported_at > timedelta(seconds=2 * settings.AGENT_HEARTBEAT_INTERVAL_SECONDS)
    sender = health.get("sender") or {}
    old_queue = False
    if oldest := health.get("oldest_queued_at"):
        try:
            old_queue = now - datetime.fromisoformat(oldest.replace("Z", "+00:00")) > BACKLOG_AGE
        except ValueError:
            old_queue = False
    if health.get("state") == "degraded":
        status, reason = "degraded", health.get("reason") or None
    elif sender.get("state") == "blocked":
        status, reason = "blocked", sender.get("reason") or None
    elif health.get("queued_events", 0) > 0 and (old_queue or sender.get("state") == "retrying"):
        status, reason = "backlogged", sender.get("reason") or "backlog"
    else:
        status, reason = "healthy", None
    return {"status": status, "reason": reason, "reported_at": reported_at.isoformat(), "stale": stale}
