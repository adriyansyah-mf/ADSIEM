# tests/worker/test_consumer_redis_loss.py
"""A Redis that restarts empty has lost the stream and its consumer group:
XREADGROUP then fails with NOGROUP on every call. The consumer must recreate
the group and keep consuming (the evidence dispatcher re-sends references to
the new stream), not log the error forever until the worker is restarted."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import consumer  # noqa: E402

REDIS_URL = os.environ.get("TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(not REDIS_URL, reason="needs TEST_REDIS_URL (a disposable Redis)")


def test_consumer_recreates_the_group_after_redis_lost_everything(monkeypatch):
    import redis.asyncio as aioredis

    async def scenario():
        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        await r.flushdb()
        seen = asyncio.Event()

        async def fake_process(data, dec, sig, predecoded=None):
            if data.get("raw_message") == "after the restart":
                seen.set()

        async def fake_get_redis():
            return r

        monkeypatch.setattr(consumer, "process_message", fake_process)
        monkeypatch.setattr(consumer, "get_redis", fake_get_redis)
        monkeypatch.setattr(consumer, "group_by_source", lambda entries, dec: [[(m, d, None) for m, d in entries]])
        loop = asyncio.create_task(consumer.consume_loop({"dec_engine": None, "sig_engine": None}))
        await asyncio.sleep(0.5)                 # group created, consumer blocked in XREADGROUP
        await r.flushdb()                        # Redis restarted without persistence
        await r.xadd(consumer.REDIS_STREAM_KEY, {"log_type": "syslog", "hostname": "h",
                                                 "raw_message": "after the restart"})
        try:
            await asyncio.wait_for(seen.wait(), timeout=20)
        finally:
            loop.cancel()
            await asyncio.gather(loop, return_exceptions=True)
            await r.flushdb()
            await r.aclose()

    asyncio.run(scenario())
