# tests/server-api/test_agent_enrollment.int.py
"""Agent enrollment against a real Postgres: reusable keys, atomic use counting,
no takeover of a connected agent, approval gating.

Needs TEST_DATABASE_URL (e.g. postgresql+asyncpg://soc:soc@localhost:5432/test) with
the pgvector extension available; skipped otherwise.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="needs TEST_DATABASE_URL (Postgres with pgvector)")


class _BG:
    def add_task(self, *a, **kw):
        pass


class _Redis:
    def __init__(self):
        self.items = []
        self.kv = {}

    async def xadd(self, *a, **kw):
        self.items.append(a)

    async def hgetall(self, key):
        return dict(self.kv.get(key) or {})

    async def hset(self, key, mapping):
        self.kv.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        pass

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True


_LOOP = asyncio.new_event_loop()  # one loop: the engine's connections are bound to it


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.database import Base
    import app.models.models  # noqa: F401 — register tables

    engine = create_async_engine(DB_URL)

    async def setup():
        async with engine.begin() as conn:
            # a fresh schema: the worker's tests share this database and leave tables
            # (e.g. case_embeddings → cases) these models don't know
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield async_sessionmaker(engine, expire_on_commit=False)
    _run(engine.dispose())


def _key(sm, **kw):
    import hashlib
    import secrets
    from app.models.models import EnrollmentToken

    raw = secrets.token_urlsafe(24)

    async def go():
        async with sm() as db:
            db.add(EnrollmentToken(token_hash=hashlib.sha256(raw.encode()).hexdigest(), label="t",
                                   group_id=kw.pop("group_id", "default"), **kw))
            await db.commit()
    _run(go())
    return raw


def _enroll(sm, key, hostname):
    from app.api.routes.agents import enroll_agent
    from app.schemas.schemas import EnrollRequest

    async def go():
        async with sm() as db:
            return await enroll_agent(EnrollRequest(enrollment_token=key, hostname=hostname, version="1.5.0",
                                                    name=""), _BG(), db)
    return _run(go())


def _status(fn):
    from fastapi import HTTPException
    try:
        fn()
    except HTTPException as exc:
        return exc.status_code, exc.detail
    return 201, None


def _agent(sm, agent_id):
    from app.models.models import Agent

    async def go():
        async with sm() as db:
            return await db.get(Agent, agent_id)
    return _run(go())


def _age(sm, agent_id, minutes):
    from sqlalchemy import update
    from app.models.models import Agent

    async def go():
        async with sm() as db:
            await db.execute(update(Agent).where(Agent.id == agent_id).values(
                last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=minutes)))
            await db.commit()
    _run(go())


def test_single_use_key_is_spent_after_one_agent(env):
    key = _key(env, max_uses=1)
    assert _enroll(env, key, "single-a").agent_token
    code, detail = _status(lambda: _enroll(env, key, "single-b"))
    assert code == 401 and "already been used" in detail


def test_deployment_key_enrolls_many_and_honours_its_limit(env):
    key = _key(env, max_uses=3, group_id="web")
    ids = [_enroll(env, key, f"web-{i}").agent_id for i in range(3)]
    assert len(set(ids)) == 3
    assert all(_agent(env, i).group_id == "web" for i in ids)  # the key decides the group
    code, detail = _status(lambda: _enroll(env, key, "web-3"))
    assert code == 401 and "limit of 3" in detail

    unlimited = _key(env, max_uses=None)
    for i in range(5):
        _enroll(env, unlimited, f"fleet-{i}")


def test_concurrent_enrollments_cannot_exceed_max_uses(env):
    from app.api.routes.agents import enroll_agent
    from app.schemas.schemas import EnrollRequest
    from fastapi import HTTPException

    key = _key(env, max_uses=2)

    async def one(i):
        async with env() as db:
            try:
                await enroll_agent(EnrollRequest(enrollment_token=key, hostname=f"race-{i}", version="1",
                                                 name=""), _BG(), db)
                return True
            except HTTPException:
                return False

    async def all_():
        return await asyncio.gather(*(one(i) for i in range(6)))
    assert sum(_run(all_())) == 2


def test_connected_agent_cannot_be_taken_over(env):
    key = _key(env, max_uses=None)
    first = _enroll(env, key, "db-01")
    code, detail = _status(lambda: _enroll(env, key, "db-01"))
    assert code == 409 and "is connected" in detail
    # once it has been quiet (rebuilt host), the same name re-enrolls in place
    _age(env, first.agent_id, minutes=5)
    again = _enroll(env, key, "db-01")
    assert again.agent_id == first.agent_id and again.agent_token != first.agent_token


def test_expired_and_revoked_keys(env):
    expired = _key(env, max_uses=None, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert _status(lambda: _enroll(env, expired, "x1"))[0] == 401
    revoked = _key(env, max_uses=None, is_active=False)
    assert _status(lambda: _enroll(env, revoked, "x2"))[0] == 401


def test_approval_gates_logs_and_tasks(env):
    from app.api.routes.agents import approve_agent
    from app.api.routes.ingest import heartbeat, ingest_log
    from app.models.models import AgentTask
    from app.schemas.schemas import HeartbeatRequest, LogIngestRequest

    key = _key(env, max_uses=None, require_approval=True)
    res = _enroll(env, key, "pending-01")
    agent = _agent(env, res.agent_id)
    assert agent.approved is False

    async def queue_task():
        async with env() as db:
            db.add(AgentTask(agent_id=agent.id, task_type="process_list", params={}, status="pending"))
            await db.commit()
    _run(queue_task())

    redis = _Redis()
    log = LogIngestRequest(agent_id=agent.id, hostname="pending-01", log_type="linux_auth", raw_message="hello",
                           received_at=datetime.now(timezone.utc))
    assert _run(ingest_log(log, agent, redis)) == {"status": "pending_approval"} and not redis.items

    async def hb(a):
        async with env() as db:
            return await heartbeat(HeartbeatRequest(agent_id=a.id, version="1.5.0"), a, db, redis)
    assert _run(hb(agent)).tasks == []

    async def do_approve():
        async with env() as db:
            return await approve_agent(agent.id, _BG(), db, current_user=type("U", (), {"id": None})(), group_filter=None)
    assert _run(do_approve()).approved is True
    agent = _agent(env, res.agent_id)
    _run(ingest_log(log, agent, redis))
    assert len(redis.items) == 1
    assert [t.task_type for t in _run(hb(agent)).tasks] == ["process_list"]


def test_heartbeat_integrity_and_stop_notice(env):
    """Integrity changes become siem_agent events; a stop notice is held for the worker."""
    from app.api.routes.ingest import heartbeat
    from app.schemas.schemas import HeartbeatRequest

    res = _enroll(env, _key(env, max_uses=None), "tamper-01")
    redis = _Redis()
    a, b, c = "a" * 64, "b" * 64, "c" * 64

    def hb(**kw):
        from app.models.models import Agent

        async def go():
            async with env() as db:
                agent = await db.get(Agent, res.agent_id)
                return await heartbeat(HeartbeatRequest(agent_id=agent.id, **kw), agent, db, redis)
        return _run(go())

    hb(version="1.7.0", integrity={"binary_sha256": a, "config_sha256": b})  # baseline
    hb(version="1.7.0", integrity={"binary_sha256": a, "config_sha256": b})
    assert redis.items == []
    hb(version="1.7.0", integrity={"binary_sha256": c, "config_sha256": b})
    assert len(redis.items) == 1
    event = redis.items[0][1]
    assert event["log_type"] == "siem_agent" and event["hostname"] == "tamper-01"
    assert event["raw_message"].startswith("event=agent_integrity_changed file=binary previous=" + a)
    hb(version="1.8.0", integrity={"binary_sha256": a, "config_sha256": b})  # upgrade: new baseline
    assert len(redis.items) == 1

    hb(version="1.8.0", status="stopping", reason="service_stop")
    agent = _agent(env, res.agent_id)
    assert (agent.status, agent.stop_reason) == ("offline", "service_stop")
    assert len(redis.items) == 1  # the worker reports it if the agent stays down
    hb(version="1.8.0")  # restarted
    agent = _agent(env, res.agent_id)
    assert (agent.status, agent.stop_reason) == ("online", None)

    # the response carries the uninstall token's hash, never the token
    from app.services.agent_tamper import uninstall_token, uninstall_token_sha256
    resp = hb(version="1.8.0")
    assert resp.uninstall_token_sha256 == uninstall_token_sha256(res.agent_id)
    assert uninstall_token(res.agent_id) not in resp.model_dump_json()

    # a second sender with the same token: sessions interleave → one event (rate-limited)
    redis.items.clear()
    for session, seq in (("real", 1), ("real", 2), ("fake", 1), ("real", 3), ("fake", 2), ("real", 4)):
        hb(version="1.8.0", session=session, seq=seq)
    anomalies = [i[1]["raw_message"] for i in redis.items]
    assert anomalies == [anomalies[0]] and "kind=duplicate_session" in anomalies[0]
