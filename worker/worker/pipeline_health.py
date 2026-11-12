# worker/worker/pipeline_health.py
"""What /health and the gauges report about the log pipeline: is Elasticsearch
reachable, how much is waiting in the stream, and how much sits in the DLQ.

Before this, /health checked only Postgres and Redis, so an Elasticsearch
outage (every line failing into the DLQ, detection hours behind) still
reported "ok"."""
from __future__ import annotations

from prometheus_client import Gauge

from worker.config import HEALTH_DLQ_WARN, HEALTH_PENDING_WARN, REDIS_STREAM_KEY

DLQ_KEY = f"{REDIS_STREAM_KEY}:failed"

queue_lag_gauge = Gauge("siem_worker_queue_lag", "Redis stream entries delivered but not yet acked")
stream_length_gauge = Gauge("siem_worker_stream_length", "Entries in the log stream")
dlq_length_gauge = Gauge("siem_worker_dlq_length", "Log lines waiting in the dead-letter queue")
es_up_gauge = Gauge("siem_worker_elasticsearch_up", "1 when Elasticsearch answers and isn't red")
redis_memory_gauge = Gauge("siem_redis_memory_used_ratio", "Redis used_memory / maxmemory (0 when uncapped)")

# Redis runs with maxmemory + noeviction (docker-compose.yml): when full, every
# write is refused, including Sigma's threshold/sequence window keys, whose
# errors are swallowed per rule. Report it well before that happens.
REDIS_MEMORY_WARN = 0.9


async def collect(redis, es_ping) -> dict:
    """One probe of the pipeline. Never raises: a failing check reports "error"."""
    state: dict = {"elasticsearch": "ok" if await es_ping() else "error"}
    es_up_gauge.set(1 if state["elasticsearch"] == "ok" else 0)
    try:
        groups = await redis.xinfo_groups(REDIS_STREAM_KEY)
        state["pending"] = sum(int(g.get("pending", 0)) for g in groups)
        state["stream_length"] = int(await redis.xlen(REDIS_STREAM_KEY))
        state["dlq"] = int(await redis.xlen(DLQ_KEY))
    except Exception:  # noqa: BLE001 — stream/group missing (fresh Redis) or Redis down
        state.update(pending=None, stream_length=None, dlq=None)
    try:
        mem = await redis.info("memory")
        cap = int(mem.get("maxmemory") or 0)
        state["redis_memory"] = round(int(mem.get("used_memory") or 0) / cap, 3) if cap else None
    except Exception:  # noqa: BLE001
        state["redis_memory"] = None
    redis_memory_gauge.set(state["redis_memory"] or 0)
    if state["pending"] is not None:
        queue_lag_gauge.set(state["pending"])
        stream_length_gauge.set(state["stream_length"])
        dlq_length_gauge.set(state["dlq"])
    return state


def overall_status(state: dict) -> str:
    if any(state.get(k) == "error" for k in ("postgres", "redis", "elasticsearch")):
        return "degraded"
    if (state.get("redis_memory") or 0) >= REDIS_MEMORY_WARN:
        return "degraded"
    if (state.get("dlq") or 0) > HEALTH_DLQ_WARN or (state.get("pending") or 0) > HEALTH_PENDING_WARN:
        return "degraded"
    return "ok"
