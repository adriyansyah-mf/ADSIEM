"""The pipeline can't fail while /health says ok: Elasticsearch, backlog and DLQ
are reported, and the DLQ is bounded and doesn't burn retries during an outage."""
import asyncio

import httpx
import pytest
import redis.exceptions as redis_exceptions
import sqlalchemy.exc

from worker import consumer, pipeline_health
from worker.config import DLQ_MAX_ATTEMPTS, DLQ_MAXLEN, HEALTH_DLQ_WARN, REDIS_STREAM_KEY


class FakePipe:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def xadd(self, key, data):
        self.ops.append(("xadd", key, data))

    def xdel(self, key, entry_id):
        self.ops.append(("xdel", key, entry_id))

    async def execute(self):
        for op, key, arg in self.ops:
            if op == "xadd":
                self.redis.streams.setdefault(key, []).append((f"{len(self.redis.streams.get(key, []))}-0", arg))
            else:
                self.redis.streams[key] = [e for e in self.redis.streams.get(key, []) if e[0] != arg]


class FakeRedis:
    def __init__(self):
        self.streams: dict[str, list] = {}
        self.xadd_kwargs: list[dict] = []
        self.groups = [{"name": "siem-workers", "pending": 7}]
        self.broken = False
        self.memory = {"used_memory": 100, "maxmemory": 1000}
        self.full = False

    async def info(self, section):
        if self.broken:
            raise ConnectionError("down")
        return self.memory

    async def xadd(self, key, data, **kw):
        if self.full:
            raise redis_exceptions.ResponseError("OOM command not allowed when used memory > 'maxmemory'.")
        self.xadd_kwargs.append(kw)
        self.streams.setdefault(key, []).append((f"{len(self.streams.get(key, []))}-0", dict(data)))

    async def xrange(self, key, count=None):
        return list(self.streams.get(key, []))[:count]

    async def xlen(self, key):
        if self.broken:
            raise ConnectionError("down")
        return len(self.streams.get(key, []))

    async def xinfo_groups(self, key):
        if self.broken:
            raise ConnectionError("down")
        return self.groups

    def pipeline(self):
        return FakePipe(self)


async def _up():
    return True


async def _down():
    return False


async def test_collect_reports_elasticsearch_backlog_and_dlq():
    redis = FakeRedis()
    redis.streams[REDIS_STREAM_KEY] = [("1-0", {}), ("2-0", {})]
    redis.streams[pipeline_health.DLQ_KEY] = [("1-0", {})]
    state = await pipeline_health.collect(redis, _down)
    assert state == {"elasticsearch": "error", "pending": 7, "stream_length": 2, "dlq": 1, "redis_memory": 0.1}
    assert pipeline_health.overall_status({"postgres": "ok", "redis": "ok", **state}) == "degraded"


async def test_collect_survives_a_missing_stream_or_redis_outage():
    redis = FakeRedis()
    redis.broken = True
    state = await pipeline_health.collect(redis, _up)
    assert state["elasticsearch"] == "ok" and state["dlq"] is None and state["pending"] is None


def test_overall_status_thresholds():
    ok = {"postgres": "ok", "redis": "ok", "elasticsearch": "ok", "pending": 0, "dlq": 0}
    assert pipeline_health.overall_status(ok) == "ok"
    assert pipeline_health.overall_status({**ok, "dlq": HEALTH_DLQ_WARN + 1}) == "degraded"
    assert pipeline_health.overall_status({**ok, "redis": "error"}) == "degraded"
    assert pipeline_health.overall_status({**ok, "dlq": None, "pending": None}) == "ok"
    assert pipeline_health.overall_status({**ok, "redis_memory": 0.95}) == "degraded"
    assert pipeline_health.overall_status({**ok, "redis_memory": None}) == "ok"   # uncapped


async def test_dead_letter_is_capped_and_counts_attempts():
    redis = FakeRedis()
    assert await consumer.dead_letter(redis, {"raw_message": "x"})
    _, parked = redis.streams[consumer.DLQ_KEY][0]
    assert parked[consumer.DLQ_ATTEMPTS_FIELD] == "1" and parked["raw_message"] == "x"
    assert redis.xadd_kwargs[0] == {"maxlen": DLQ_MAXLEN, "approximate": True}
    assert await consumer.dead_letter(redis, parked)
    assert redis.streams[consumer.DLQ_KEY][1][1][consumer.DLQ_ATTEMPTS_FIELD] == "2"


async def test_a_poison_message_is_dropped_after_max_attempts():
    redis = FakeRedis()
    poison = {"raw_message": "x", consumer.DLQ_ATTEMPTS_FIELD: str(DLQ_MAX_ATTEMPTS)}
    assert not await consumer.dead_letter(redis, poison)
    assert consumer.DLQ_KEY not in redis.streams


async def test_dlq_retry_waits_for_elasticsearch():
    redis = FakeRedis()
    redis.streams[consumer.DLQ_KEY] = [("1-0", {"raw_message": "a", consumer.DLQ_ATTEMPTS_FIELD: "1"})]
    assert await consumer.dlq_retry_once(redis, _down) == 0
    assert len(redis.streams[consumer.DLQ_KEY]) == 1           # kept, no attempt used
    assert await consumer.dlq_retry_once(redis, _up) == 1
    assert redis.streams[consumer.DLQ_KEY] == []
    replayed = redis.streams[REDIS_STREAM_KEY][0][1]
    assert replayed["raw_message"] == "a" and replayed[consumer.DLQ_ATTEMPTS_FIELD] == "1"


async def test_failed_line_goes_to_the_capped_dlq(monkeypatch):
    redis = FakeRedis()
    acked = []

    async def xack(*a):
        acked.append(a[-1])

    redis.xack = xack

    async def boom(*a, **kw):
        raise RuntimeError("elasticsearch down")

    monkeypatch.setattr(consumer, "process_message", boom)
    await consumer._process_group(redis, [("9-0", {"raw_message": "y"}, None)], None, None, asyncio.Semaphore(1))
    assert acked == ["9-0"]
    assert redis.streams[consumer.DLQ_KEY][0][1][consumer.DLQ_ATTEMPTS_FIELD] == "1"


def test_worker_main_imports_and_uses_the_pipeline_probe():
    # the old probe referenced REDIS_STREAM_KEY without importing it; the NameError
    # was swallowed, so siem_worker_queue_lag was never set
    import inspect
    from worker import main
    src = inspect.getsource(main.health_probe_loop)
    assert "pipeline_health.collect" in src and "REDIS_STREAM_KEY" not in src


def _status_error(code):
    request = httpx.Request("PUT", "http://es/logs/_doc/1")
    return httpx.HTTPStatusError("x", request=request, response=httpx.Response(code, request=request))


@pytest.mark.parametrize("exc,infra", [
    (_status_error(503), True),
    (_status_error(429), True),
    (_status_error(403), True),          # read-only index (flood-stage disk)
    (_status_error(400), False),         # this document is bad
    (httpx.ConnectError("refused"), True),
    (sqlalchemy.exc.OperationalError("SELECT 1", {}, Exception("pg down")), True),
    (redis_exceptions.ConnectionError("down"), True),
    (asyncio.TimeoutError(), True),
    (KeyError("source.ip"), False),
    (ValueError("bad"), False),
])
def test_infrastructure_errors_are_told_apart_from_bad_lines(exc, infra):
    assert consumer.is_infrastructure_error(exc) is infra


async def test_an_outage_does_not_use_up_attempts():
    redis = FakeRedis()
    line = {"raw_message": "x", consumer.DLQ_ATTEMPTS_FIELD: str(DLQ_MAX_ATTEMPTS)}
    # at the limit already, but Postgres being down is not the line's fault
    pg_down = sqlalchemy.exc.OperationalError("SELECT 1", {}, Exception("down"))
    assert await consumer.dead_letter(redis, line, pg_down)
    assert redis.streams[consumer.DLQ_KEY][0][1][consumer.DLQ_ATTEMPTS_FIELD] == str(DLQ_MAX_ATTEMPTS)
    assert not await consumer.dead_letter(redis, line, ValueError("bad line"))


async def test_a_line_stays_pending_when_the_dlq_write_fails(monkeypatch):
    redis = FakeRedis()
    redis.full = True                       # Redis at maxmemory with noeviction
    acked = []

    async def xack(*a):
        acked.append(a[-1])

    redis.xack = xack
    calls = []

    async def process(data, *a, **kw):
        calls.append(data["raw_message"])
        if data["raw_message"] == "bad":
            raise ValueError("bad line")

    monkeypatch.setattr(consumer, "process_message", process)
    group = [("1-0", {"raw_message": "bad"}, None), ("2-0", {"raw_message": "good"}, None)]
    await consumer._process_group(redis, group, None, None, asyncio.Semaphore(1))
    assert calls == ["bad", "good"]         # the rest of the group still ran
    assert acked == ["2-0"]                 # the failed line is not acked, so it isn't lost
