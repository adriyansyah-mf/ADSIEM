"""On-demand TI lookups for the investigation chat: queue -> aggregator -> result key."""
import asyncio
import json

import pytest

from worker import ti_lookup


class FakeRedis:
    def __init__(self):
        self.lists: dict[str, list[str]] = {}
        self.store: dict[str, str] = {}
        self.ttl: dict[str, int] = {}

    async def blpop(self, key, timeout=0):
        items = self.lists.get(key) or []
        if not items:
            await asyncio.sleep(0.01)
            return None
        return key, items.pop(0)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        if ex:
            self.ttl[key] = ex

    def push(self, payload):
        self.lists.setdefault(ti_lookup.QUEUE, []).append(payload if isinstance(payload, str) else json.dumps(payload))


class Summary:
    def model_dump(self, mode="json"):
        return {"iocs": [], "reputation": [{"ioc_value": "8.8.8.8", "malicious": True, "sources": ["vt"]}],
                "provider_bullets": ["vt: 5 engines"], "overall_risk": 0.9, "triage_hints": []}


class Aggregator:
    def __init__(self, fail=False):
        self.fail, self.seen = fail, []

    async def enrich(self, text, alert_title=""):
        self.seen.append(text)
        if self.fail:
            raise RuntimeError("provider down")
        return Summary()


def job(value, id="j1"):
    return {"id": id, "value": value, "group": "blue", "requested_at": "2026-11-09T00:00:00Z"}


async def test_result_written_with_ttl():
    r, agg = FakeRedis(), Aggregator()
    await ti_lookup.handle(r, json.dumps(job("198.41.0.4")), agg)
    out = json.loads(r.store["siem:ti:result:j1"])
    assert out["overall_risk"] == 0.9 and out["reputation"][0]["malicious"] is True
    assert r.ttl["siem:ti:result:j1"] == 600
    assert agg.seen == ["198.41.0.4"]


async def test_error_written_when_aggregator_fails():
    r = FakeRedis()
    await ti_lookup.handle(r, json.dumps(job("evil.example.com")), Aggregator(fail=True))
    assert "provider down" in json.loads(r.store["siem:ti:result:j1"])["error"]


@pytest.mark.parametrize("value", ["", "two words here", "x" * 600, "8.8.8.8 and evil.com", "not_a_domain",
                                   "10.0.0.5", "127.0.0.1", "ftp://x.com/a", "abc123"])
async def test_bad_value_rejected_without_calling_aggregator(value):
    r, agg = FakeRedis(), Aggregator()
    await ti_lookup.handle(r, json.dumps(job(value)), agg)
    assert "error" in json.loads(r.store["siem:ti:result:j1"])
    assert agg.seen == []


@pytest.mark.parametrize("value", ["8.8.8.8", "evil.example.com", "https://evil.example.com/a?b=1",
                                   "d41d8cd98f00b204e9800998ecf8427e", "a" * 40, "b" * 64])
async def test_single_iocs_accepted(value):
    r, agg = FakeRedis(), Aggregator()
    await ti_lookup.handle(r, json.dumps(job(value)), agg)
    assert "error" not in json.loads(r.store["siem:ti:result:j1"])


async def test_malformed_job_does_not_raise():
    r = FakeRedis()
    await ti_lookup.handle(r, "{not json", Aggregator())
    await ti_lookup.handle(r, json.dumps({"value": "8.8.8.8"}), Aggregator())  # no id
    assert r.store == {}


async def test_loop_survives_an_exception_and_serves_next_job():
    r = FakeRedis()
    calls = []

    class Flaky:
        async def enrich(self, text, alert_title=""):
            calls.append(text)
            if len(calls) == 1:
                raise ValueError("boom")
            return Summary()

    async def factory():
        return Flaky()

    r.push(job("8.8.4.4", "a"))
    r.push(job("1.1.1.1", "b"))
    task = asyncio.create_task(ti_lookup.ti_lookup_loop(r, aggregator_factory=factory))
    for _ in range(200):
        if "siem:ti:result:b" in r.store:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "error" in json.loads(r.store["siem:ti:result:a"])
    assert "overall_risk" in json.loads(r.store["siem:ti:result:b"])


async def test_loop_survives_a_failing_redis_pop():
    class Broken(FakeRedis):
        n = 0

        async def blpop(self, key, timeout=0):
            self.n += 1
            if self.n == 1:
                raise ConnectionError("redis away")
            return await super().blpop(key, timeout)

    r = Broken()
    r.push(job("8.8.8.8"))

    async def factory():
        return Aggregator()

    task = asyncio.create_task(ti_lookup.ti_lookup_loop(r, aggregator_factory=factory, retry_delay=0.01))
    for _ in range(200):
        if "siem:ti:result:j1" in r.store:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "siem:ti:result:j1" in r.store
