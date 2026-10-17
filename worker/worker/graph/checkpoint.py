# worker/worker/graph/checkpoint.py
"""Per-alert lock for the triage graph.

The worker runs 2 replicas consuming one Redis stream. Without a lock, a
redelivered or concurrently-claimed alert could be triaged twice, creating
duplicate cases and firing SOAR playbook actions (isolate/block) twice. The
lock is compare-and-delete so a run that outlived its TTL cannot release a
successor's lock.
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
    """Yield True when this replica owns the alert's triage lock."""
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
