"""Checkpointer factories for the agent graphs.

Two distinct policies, because the graphs have different execution models:

- The assistant graph is single-replica and interactive: it gets the Redis
  saver, so a run survives a restart and can be resumed.
- The worker triage graph runs on 2 replicas consuming one Redis stream. A
  shared saver would let both replicas resume the same interrupted run and
  double-execute side effects (case creation, SOAR playbook actions), so it
  gets an in-memory saver plus a per-alert lock held around the whole run.
"""
from __future__ import annotations

import contextlib
from typing import AsyncIterator

from langgraph.checkpoint.memory import InMemorySaver

_lock_release_script = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


def ephemeral_saver() -> InMemorySaver:
    """Per-process saver for graphs that must not share state across replicas."""
    return InMemorySaver()


@contextlib.asynccontextmanager
async def redis_saver(redis_url: str) -> AsyncIterator:
    """Redis-backed saver for the interactive assistant graph."""
    from langgraph.checkpoint.redis.aio import AsyncRedisSaver

    async with AsyncRedisSaver.from_conn_string(redis_url) as saver:
        await saver.asetup()
        yield saver


@contextlib.asynccontextmanager
async def triage_lock(redis, alert_id: str, ttl_seconds: int = 120) -> AsyncIterator[bool]:
    """Best-effort mutual exclusion so replicas don't both triage one alert.

    Yields True when this process owns the lock and should run the graph; False
    when another replica is already handling it. The lock is released only if we
    still own it (compare-and-delete), so a run that outlived its TTL cannot
    delete a successor's lock.
    """
    import secrets

    key = f"triage:lock:{alert_id}"
    token = secrets.token_hex(16)
    acquired = await redis.set(key, token, nx=True, ex=ttl_seconds)
    try:
        yield bool(acquired)
    finally:
        if acquired:
            try:
                await redis.eval(_lock_release_script, 1, key, token)
            except Exception:
                pass
