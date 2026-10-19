# worker/worker/stream_maintenance.py
"""Keep the log stream (siem:logs) bounded.

Workers XACK what they process but nothing ever deleted it, so the stream kept
every log since the platform started — millions of entries, until Redis hit
its memory limit, was killed on its next background save, and crash-looped
(reloading the same multi-GB snapshot each time). Every minute this:

- re-queues messages left pending on a consumer that died mid-batch (each
  worker container is a new consumer name, so nobody else would ever take
  them), so they are processed instead of pinning the stream forever;
- removes consumers that are idle and hold nothing;
- trims everything already processed: entries older than both the group's
  last-delivered id and its oldest pending message. Unread and in-flight
  entries are never removed.
"""
import asyncio

import structlog

from worker.config import REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY
from worker.consumer import CONSUMER_NAME
from worker.redis_client import get_redis

log = structlog.get_logger()

INTERVAL = 60
STALE_PENDING_MS = 10 * 60 * 1000    # pending this long: its consumer is gone
IDLE_CONSUMER_MS = 60 * 60 * 1000
CLAIM_BATCH = 200
TRIM_APPROXIMATE = True  # whole internal nodes only: cheap; the boundary node is trimmed later


def _id(stream_id: str) -> tuple[int, int]:
    ms, _, seq = str(stream_id).partition("-")
    return int(ms), int(seq or 0)


def safe_trim_id(last_delivered: str | None, oldest_pending: str | None) -> str | None:
    """The id below which every entry is processed: the older of the group's
    last-delivered id and its oldest pending message."""
    ids = [i for i in (last_delivered, oldest_pending) if i and i != "0-0"]
    return min(ids, key=_id) if ids else None


async def maintain_stream(redis) -> dict:
    stats = {"requeued": 0, "consumers_removed": 0, "trimmed": 0}
    key, group = REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP

    start = "0-0"
    while True:
        reply = await redis.xautoclaim(key, group, CONSUMER_NAME, min_idle_time=STALE_PENDING_MS,
                                       start_id=start, count=CLAIM_BATCH)
        start, claimed = reply[0], reply[1]
        for msg_id, data in claimed:
            if data:  # still in the stream: hand it to the consume loop again
                await redis.xadd(key, data)
            await redis.xack(key, group, msg_id)
            stats["requeued"] += 1
        if not claimed or start in ("0-0", b"0-0"):
            break

    for consumer in await redis.xinfo_consumers(key, group):
        if (consumer["name"] != CONSUMER_NAME and not consumer["pending"]
                and consumer["idle"] > IDLE_CONSUMER_MS):
            await redis.xgroup_delconsumer(key, group, consumer["name"])
            stats["consumers_removed"] += 1

    info = next((g for g in await redis.xinfo_groups(key) if g["name"] == group), None)
    if info:
        pending = await redis.xpending(key, group)
        cutoff = safe_trim_id(info.get("last-delivered-id"), pending.get("min") if pending["pending"] else None)
        if cutoff:
            stats["trimmed"] = await redis.xtrim(key, minid=cutoff, approximate=TRIM_APPROXIMATE)
    return stats


async def stream_maintenance_loop() -> None:
    while True:
        try:
            stats = await maintain_stream(await get_redis())
            if any(stats.values()):
                log.info("log_stream_maintained", **stats)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — try again next round
            log.warning("log_stream_maintenance_failed", error=str(exc))
        await asyncio.sleep(INTERVAL)
