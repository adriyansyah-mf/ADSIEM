"""Per-alert lock for the triage graph.

The worker runs 2 replicas consuming one Redis stream. Without a lock, a
redelivered or concurrently-claimed alert could be triaged twice, creating
duplicate cases and firing SOAR playbook actions (isolate/block) twice.

Uses plain Redis SET NX + compare-and-delete rather than a LangGraph redis
checkpointer: those need the RedisJSON and RediSearch modules, which the
deployed redis image does not provide.
"""
from __future__ import annotations

import contextlib
import secrets
from typing import AsyncIterator

_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


@contextlib.asynccontextmanager
async def triage_lock(redis, alert_id: str, ttl_seconds: int = 120) -> AsyncIterator[bool]:
    """Best-effort mutual exclusion so replicas don't both triage one alert.

    Yields True when this process owns the lock and should run the graph; False
    when another replica is already handling it. The lock is released only if we
    still own it (compare-and-delete), so a run that outlived its TTL cannot
    delete a successor's lock.
    """
    key = f"triage:lock:{alert_id}"
    token = secrets.token_hex(16)
    acquired = await redis.set(key, token, nx=True, ex=ttl_seconds)
    try:
        yield bool(acquired)
    finally:
        if acquired:
            try:
                await redis.eval(_RELEASE_SCRIPT, 1, key, token)
            except Exception:
                pass
