# tests/worker/test_stream_maintenance.py
"""The log stream is trimmed to what's unprocessed, stuck messages of dead
consumers are re-queued, idle consumers removed. The Redis test needs
TEST_REDIS_URL (a throwaway Redis 7)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker import stream_maintenance as sm  # noqa: E402


def test_safe_trim_id_keeps_unread_and_in_flight_entries():
    assert sm.safe_trim_id("1700000000500-0", None) == "1700000000500-0"
    assert sm.safe_trim_id("1700000000500-0", "1700000000100-3") == "1700000000100-3"
    assert sm.safe_trim_id("1700000000100-0", "1700000000500-0") == "1700000000100-0"
    assert sm.safe_trim_id("1700000000100-10", "1700000000100-9") == "1700000000100-9"  # seq compared as int
    assert sm.safe_trim_id("0-0", None) is None  # nothing delivered yet: trim nothing


class FullRedis:
    """Redis at maxmemory with noeviction: XADD is refused, XACK and XTRIM work."""

    def __init__(self, stuck):
        self.stuck, self.acked, self.added, self.trimmed_at = stuck, [], [], None

    async def xautoclaim(self, key, group, consumer, min_idle_time, start_id, count):
        claimed, self.stuck = self.stuck, []
        return ["0-0", claimed, []]

    async def xadd(self, key, data, **_):
        from redis.exceptions import OutOfMemoryError
        raise OutOfMemoryError("command not allowed when used memory > 'maxmemory'.")

    async def xack(self, key, group, *ids):
        self.acked.extend(ids)

    async def xinfo_consumers(self, key, group):
        return []

    async def xinfo_groups(self, key):
        return [{"name": sm.REDIS_CONSUMER_GROUP, "last-delivered-id": "1700000000500-0"}]

    async def xpending(self, key, group):
        return {"pending": 0}

    async def xtrim(self, key, minid, approximate):
        self.trimmed_at = minid
        return 1234


def test_trim_still_runs_when_redis_refuses_writes():
    redis = FullRedis([("1-0", {"kind": "evidence_v2", "receipt_id": "r1"}), ("2-0", {"log_type": "syslog"})])
    stats = asyncio.run(sm.maintain_stream(redis))
    # the evidence reference is only acked (the inbox resends it); the log line could not be re-queued
    assert redis.acked == ["1-0"]
    assert stats["trimmed"] == 1234 and redis.trimmed_at == "1700000000500-0"


@pytest.mark.skipif(not os.environ.get("TEST_REDIS_URL"), reason="needs TEST_REDIS_URL")
def test_maintenance_on_a_real_stream(monkeypatch):
    import redis.asyncio as aioredis

    key, group = "test:logs", "test-workers"
    monkeypatch.setattr(sm, "REDIS_STREAM_KEY", key)
    monkeypatch.setattr(sm, "REDIS_CONSUMER_GROUP", group)
    monkeypatch.setattr(sm, "CONSUMER_NAME", "worker-live")
    monkeypatch.setattr(sm, "STALE_PENDING_MS", 0)
    monkeypatch.setattr(sm, "IDLE_CONSUMER_MS", 0)
    monkeypatch.setattr(sm, "TRIM_APPROXIMATE", False)  # exact, to check the boundary

    async def go():
        r = aioredis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True)
        await r.delete(key)
        await r.xgroup_create(key, group, id="0", mkstream=True)
        ids = [await r.xadd(key, {"n": str(i)}) for i in range(10)]
        # a dead consumer read 4 and acked 3; the 4th is stuck pending
        got = await r.xreadgroup(group, "worker-dead", {key: ">"}, count=4)
        await r.xack(key, group, *[i for i, _ in got[0][1][:3]])
        stuck = got[0][1][3]
        await asyncio.sleep(0.01)

        stats = await sm.maintain_stream(r)
        assert stats["requeued"] == 1 and stats["consumers_removed"] == 1 and stats["trimmed"] == 3
        names = [c["name"] for c in await r.xinfo_consumers(key, group)]
        assert "worker-dead" not in names
        remaining = [i for i, _ in await r.xrange(key)]
        # the 3 processed entries are gone; the 6 unread ones stay (and the last delivered
        # one, the trim's boundary); the stuck message is re-queued at the end for the live workers
        assert remaining[:7] == ids[3:]
        assert len(remaining) == 8 and (await r.xrange(key, remaining[-1], remaining[-1]))[0][1] == stuck[1]
        assert len(await r.xreadgroup(group, "worker-live", {key: ">"}, count=20)) == 1  # all unread still readable
        await r.delete(key)
        await r.aclose()
    asyncio.run(go())
