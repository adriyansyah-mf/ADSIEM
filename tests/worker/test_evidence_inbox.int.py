# tests/worker/test_evidence_inbox.int.py
"""The durable inbox's worker half: the database owns delivery, Redis only
carries references. Lost, trimmed or duplicate references and Redis outages
cannot lose evidence; failures retry with backoff and dead-letter at 20;
completion commits before the reference is acked; retention releases payloads
and group budget after 7 days and receipts after 30.

Needs TEST_DATABASE_URL naming a disposable PostgreSQL; every test gets its
own schema, dropped afterwards (never the public schema). The real-stream test
also needs TEST_REDIS_URL."""
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4, uuid5

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
from sqlalchemy import select, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from worker import consumer, evidence_inbox as ei  # noqa: E402
from worker.models import EvidenceGroupUsage, EvidenceInbox  # noqa: E402

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="needs TEST_DATABASE_URL (disposable PostgreSQL)")

ENVELOPE = json.loads((Path(__file__).parents[1] / "fixtures/evidence-v2.json").read_text())
AGENT = UUID(ENVELOPE["agent_id"])
COLLECTED = datetime(2026, 10, 21, 1, 2, 3, 123456, tzinfo=timezone.utc)


class FakeRedis:
    """XADD through a non-transactional pipeline, like redis.asyncio."""

    def __init__(self):
        self.stream: list[dict] = []
        self.down = False

    def pipeline(self, transaction=True):
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def xadd(self, key, fields, **_):
        self.ops.append(fields)
        return self

    async def execute(self):
        if self.redis.down:
            raise ConnectionError("redis unavailable")
        self.redis.stream.extend(self.ops)
        return [f"{len(self.redis.stream)}-0" for _ in self.ops]


@pytest.fixture
async def env(monkeypatch):
    namespace = "evidence_worker_" + uuid4().hex
    admin = create_async_engine(DB_URL)
    async with admin.begin() as db:
        await db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_async_engine(
        DB_URL, connect_args={"server_settings": {"search_path": namespace}},
        execution_options={"schema_translate_map": {None: namespace}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.run_sync(lambda sync: EvidenceInbox.metadata.create_all(
                sync, tables=[EvidenceInbox.__table__, EvidenceGroupUsage.__table__]))
        redis = FakeRedis()
        calls: list[dict] = []
        behaviour = {"fail": 0, "sleep": 0.0}

        async def fake_process(data, dec, sig, predecoded=None, event_id=None):
            calls.append({**data, "event_id": event_id})
            if behaviour["sleep"]:
                await asyncio.sleep(behaviour["sleep"])
            if behaviour["fail"]:
                behaviour["fail"] -= 1
                raise RuntimeError("elasticsearch unavailable")

        async def fake_get_redis():
            return redis

        monkeypatch.setattr(ei, "AsyncSessionLocal", sessions)
        monkeypatch.setattr(ei, "get_redis", fake_get_redis)
        monkeypatch.setattr(consumer, "process_message", fake_process)
        monkeypatch.setattr(ei, "BUSY_RETRIES", 2)
        monkeypatch.setattr(ei, "BUSY_WAIT_SECONDS", 0.01)
        yield SimpleNamespace(sessions=sessions, redis=redis, calls=calls, behaviour=behaviour,
                              state={"dec_engine": None, "sig_engine": None})
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()


async def seed(env, n=1, group="g1", **values) -> list[EvidenceInbox]:
    rows = []
    async with env.sessions() as db:
        for _ in range(n):
            envelope = {**ENVELOPE, "event_id": str(uuid4())}
            payload = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            row = EvidenceInbox(
                agent_id=AGENT, event_id=UUID(envelope["event_id"]), group_id=group, hostname="server-host",
                payload_digest="0" * 64, payload=payload,
                payload_bytes=len(json.dumps(payload, ensure_ascii=False).encode()), collected_at=COLLECTED,
                **values,
            )
            db.add(row)
            rows.append(row)
        usage = await db.get(EvidenceGroupUsage, group)
        added = sum(r.payload_bytes for r in rows)
        if usage is None:
            db.add(EvidenceGroupUsage(group_id=group, payload_bytes=added))
        else:
            usage.payload_bytes += added
        await db.commit()
    return rows


async def get(env, receipt_id) -> EvidenceInbox:
    async with env.sessions() as db:
        return await db.get(EvidenceInbox, receipt_id)


def now() -> datetime:
    return datetime.now(timezone.utc)


async def test_dispatched_reference_is_immediately_processable(env):
    [row] = await seed(env)
    assert await ei.dispatch_once(now()) == 1
    assert env.redis.stream == [{"kind": "evidence_v2", "receipt_id": str(row.receipt_id),
                                 "group_id": "g1", "hostname": "server-host"}]
    dispatched = await get(env, row.receipt_id)
    assert dispatched.next_dispatch_at > now() and dispatched.dispatch_count == 1
    assert await ei.dispatch_once(now()) == 0  # throttled until next_dispatch_at

    # next_dispatch_at moved into the future; the worker must not treat that as a retry delay
    assert await ei.process_reference(row.receipt_id, env.state) == "completed"
    done = await get(env, row.receipt_id)
    assert done.status == "completed" and done.completed_at is not None

    [call] = env.calls
    assert call["event_id"] == uuid5(AGENT, str(row.event_id)) == ei.evidence_event_id(AGENT, row.event_id)
    assert call["raw_message"] == "a\n\x00b 世界"          # NUL and Unicode survive the JSONB string
    assert call["agent_id"] == str(AGENT) and call["group_id"] == "g1" and call["hostname"] == "server-host"
    assert call["log_type"] == "syslog" and call["location"] == "/logs"
    assert datetime.fromisoformat(call["received_at"]) == COLLECTED  # original collection time


async def test_duplicate_references_process_once(env):
    [row] = await seed(env)
    outcomes = [await ei.process_reference(row.receipt_id, env.state) for _ in range(3)]
    assert outcomes == ["completed", "duplicate", "duplicate"]
    assert len(env.calls) == 1


async def test_concurrent_dispatchers_send_each_receipt_once(env):
    rows = await seed(env, n=30)
    counts = await asyncio.gather(ei.dispatch_once(now()), ei.dispatch_once(now()), ei.dispatch_once(now()))
    assert sum(counts) == 30
    sent = [ref["receipt_id"] for ref in env.redis.stream]
    assert sorted(sent) == sorted(str(r.receipt_id) for r in rows)


async def test_redis_outage_leaves_rows_dispatchable(env):
    [row] = await seed(env)
    env.redis.down = True
    assert await ei.dispatch_once(now()) == 0
    unchanged = await get(env, row.receipt_id)
    assert unchanged.dispatch_count == 0 and unchanged.next_dispatch_at <= now()
    env.redis.down = False
    assert await ei.dispatch_once(now()) == 1


async def test_trimmed_reference_is_redispatched(env):
    [row] = await seed(env)
    assert await ei.dispatch_once(now()) == 1
    env.redis.stream.clear()  # trimmed / lost before any worker read it
    assert await ei.dispatch_once(now()) == 0
    assert await ei.dispatch_once(now() + timedelta(seconds=ei.REDISPATCH_SECONDS + 1)) == 1
    assert env.redis.stream[0]["receipt_id"] == str(row.receipt_id)
    assert (await get(env, row.receipt_id)).dispatch_count == 2


async def test_failure_after_indexing_retries_with_the_same_identity(env):
    [row] = await seed(env)
    env.behaviour["fail"] = 1  # crashed after Elasticsearch, before completion
    assert await ei.process_reference(row.receipt_id, env.state) == "deferred"
    failed = await get(env, row.receipt_id)
    assert failed.status == "pending" and failed.failure_count == 1
    assert "elasticsearch unavailable" in failed.last_error
    assert failed.next_attempt_at > now()
    assert failed.next_dispatch_at >= failed.next_attempt_at  # dispatcher wakes it when eligible

    assert await ei.process_reference(row.receipt_id, env.state) == "deferred"  # too early: not attempted
    assert len(env.calls) == 1
    later = failed.next_attempt_at + timedelta(seconds=1)
    assert await ei.process_reference(row.receipt_id, env.state, now=later) == "completed"
    assert [c["event_id"] for c in env.calls] == [ei.evidence_event_id(AGENT, row.event_id)] * 2


async def test_twenty_failures_dead_letter_and_keep_the_payload(env):
    [row] = await seed(env)
    env.behaviour["fail"] = 100
    when, outcomes, delays = now(), [], []
    for _ in range(ei.MAX_FAILURES):
        outcomes.append(await ei.process_reference(row.receipt_id, env.state, now=when))
        current = await get(env, row.receipt_id)
        delays.append((current.next_attempt_at - when).total_seconds())
        when = current.next_attempt_at + timedelta(seconds=1)
    assert outcomes == ["deferred"] * (ei.MAX_FAILURES - 1) + ["dead_letter"]
    assert max(delays) <= ei.RETRY_CAP_SECONDS + 1
    dead = await get(env, row.receipt_id)
    assert dead.status == "dead_letter" and dead.failure_count == ei.MAX_FAILURES and dead.payload is not None
    calls = len(env.calls)
    assert await ei.process_reference(row.receipt_id, env.state, now=when) == "dead_letter"
    assert len(env.calls) == calls
    assert await ei.dispatch_once(when) == 0  # never redispatched


async def test_timeout_releases_the_row_and_counts_one_failure(env, monkeypatch):
    [row] = await seed(env)
    monkeypatch.setattr(ei, "PROCESS_TIMEOUT_SECONDS", 0.2)
    env.behaviour["sleep"] = 5
    assert await ei.process_reference(row.receipt_id, env.state) == "deferred"
    async with env.sessions() as db:  # lock released: NOWAIT succeeds
        locked = (await db.execute(select(EvidenceInbox).where(
            EvidenceInbox.receipt_id == row.receipt_id).with_for_update(nowait=True))).scalar_one()
        assert locked.failure_count == 1 and "Timeout" in locked.last_error
        await db.rollback()


async def test_busy_and_missing_references(env):
    [row] = await seed(env)
    assert await ei.process_reference(uuid4(), env.state) == "missing"
    async with env.sessions() as holder:
        await holder.execute(select(EvidenceInbox).where(
            EvidenceInbox.receipt_id == row.receipt_id).with_for_update())
        assert await ei.process_reference(row.receipt_id, env.state) == "busy"
        await holder.rollback()
    assert await ei.process_reference(row.receipt_id, env.state) == "completed"
    assert len(env.calls) == 1


async def test_retention_releases_payloads_then_receipts(env):
    t = now()
    fresh = (await seed(env, status="completed", completed_at=t - timedelta(days=1)))[0]
    aged = (await seed(env, status="completed", completed_at=t - timedelta(days=8)))[0]
    old = (await seed(env, status="completed", completed_at=t - timedelta(days=31)))[0]
    pending = (await seed(env, received_at=t - timedelta(days=40)))[0]
    dead = (await seed(env, status="dead_letter", received_at=t - timedelta(days=40)))[0]
    async with env.sessions() as db:
        before = (await db.get(EvidenceGroupUsage, "g1")).payload_bytes

    assert await ei.evidence_retention_once(t) == 3  # two payloads released, one receipt deleted
    assert (await get(env, fresh.receipt_id)).payload is not None
    released = await get(env, aged.receipt_id)
    assert released.payload is None and released.status == "completed"
    assert await get(env, old.receipt_id) is None
    assert (await get(env, pending.receipt_id)).payload is not None
    assert (await get(env, dead.receipt_id)).payload is not None
    async with env.sessions() as db:
        assert (await db.get(EvidenceGroupUsage, "g1")).payload_bytes == before - aged.payload_bytes - old.payload_bytes
        assert await db.scalar(text("SELECT count(*) FROM evidence_inbox WHERE payload = 'null'::jsonb")) == 0

    assert await ei.evidence_retention_once(t) == 0  # idempotent: nothing released twice
    # 23 days on: the aged receipt is 31 days old (deleted), the fresh payload 24 days (released)
    assert await ei.evidence_retention_once(t + timedelta(days=23)) == 2
    assert await get(env, aged.receipt_id) is None
    assert (await get(env, fresh.receipt_id)).payload is None


@pytest.mark.skipif(not os.environ.get("TEST_REDIS_URL"), reason="needs TEST_REDIS_URL")
async def test_dispatch_to_a_real_stream(env, monkeypatch):
    import redis.asyncio as aioredis

    key = "test:evidence:" + uuid4().hex
    real = aioredis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True)

    async def real_redis():
        return real

    monkeypatch.setattr(ei, "get_redis", real_redis)
    monkeypatch.setattr(ei, "REDIS_STREAM_KEY", key)
    try:
        rows = await seed(env, n=3)
        assert await ei.dispatch_once(now()) == 3
        entries = await real.xrange(key)
        assert sorted(f["receipt_id"] for _, f in entries) == sorted(str(r.receipt_id) for r in rows)
        assert all(f["kind"] == "evidence_v2" for _, f in entries)
    finally:
        await real.delete(key)
        await real.aclose()
