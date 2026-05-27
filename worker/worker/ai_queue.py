# worker/worker/ai_queue.py
# Shared helpers for the AI analysis queue — kept separate to avoid circular imports.
AI_QUEUED_SET = "siem:ai:queued_alerts"

async def mark_queued(redis, alert_id: str) -> bool:
    """Add alert_id to the queued set. Returns True if newly added (False if already queued)."""
    return bool(await redis.sadd(AI_QUEUED_SET, alert_id))
