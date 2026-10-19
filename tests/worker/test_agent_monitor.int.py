# tests/worker/test_agent_monitor.int.py
"""agent_monitor's tamper events against a real Postgres: silent agents, stops
that last, restarts that don't, and a fleet-wide outage.

Needs TEST_DATABASE_URL = DATABASE_URL (worker.database binds its engine at import).
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


class FakeRedis:
    def __init__(self):
        self.events = []
        self.kv = {}

    async def xadd(self, _stream, data):
        self.events.append(data)

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = str(value)
        return True

    async def delete(self, key):
        self.kv.pop(key, None)


@pytest.fixture()
def env(monkeypatch):
    from sqlalchemy import text

    from worker import agent_monitor
    from worker.database import engine
    from worker.models import Base

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    redis = FakeRedis()

    async def fake_get_redis():
        return redis

    async def fake_setting(key, default=""):
        return "60" if key == "agent_log_silence_minutes" else default
    monkeypatch.setattr(agent_monitor, "get_redis", fake_get_redis)
    monkeypatch.setattr(agent_monitor, "get_setting", fake_setting)
    yield redis
    _run(engine.dispose())  # its connections are bound to this module's loop


def _agents(*rows):
    from worker.database import AsyncSessionLocal
    from worker.models import Agent

    async def go():
        async with AsyncSessionLocal() as s:
            for row in rows:
                s.add(Agent(id=uuid.uuid4(), group_id="blue", **row))
            await s.commit()
    _run(go())


def _sweep():
    from worker import agent_monitor
    from worker.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as s:
            await agent_monitor._mark_offline(s)
            await agent_monitor._report_stops(s)
            await agent_monitor._check_quiet_agents(s)
    _run(go())


def _ago(seconds):
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _events(redis):
    return [(e["hostname"], e["raw_message"].split()[0]) for e in redis.events]


def test_silent_and_stopped_agents_are_reported_once(env):
    _agents(
        dict(hostname="silent", status="online", last_seen_at=_ago(400)),
        dict(hostname="fresh", status="online", last_seen_at=_ago(10)),
        dict(hostname="never-seen", status="online", last_seen_at=None),
        dict(hostname="pending", status="online", last_seen_at=_ago(400), approved=False),
        # stop notices: one older than the grace period, one a restart still in progress
        dict(hostname="stopped", status="offline", last_seen_at=_ago(200), stop_reason="service_stop", version="1.7.0"),
        dict(hostname="restarting", status="offline", last_seen_at=_ago(30), stop_reason="service_stop"),
        dict(hostname="rebooted", status="offline", last_seen_at=_ago(200), stop_reason="system_shutdown"),
    )
    _sweep()
    assert sorted(_events(env)) == [
        ("rebooted", "event=agent_stopped"),  # sent, but the rule only alerts on service_stop
        ("silent", "event=agent_offline"),
        ("stopped", "event=agent_stopped"),
    ]
    stopped = next(e for e in env.events if e["hostname"] == "stopped")
    assert "reason=service_stop" in stopped["raw_message"] and "version=1.7.0" in stopped["raw_message"]
    assert stopped["log_type"] == "siem_agent" and stopped["group_id"] == "blue"

    env.events.clear()
    _sweep()
    assert env.events == []  # each stop and silence is reported once


def test_half_the_fleet_offline_is_one_event(env):
    _agents(*[dict(hostname=f"web{i}", status="online", last_seen_at=_ago(400)) for i in range(6)],
            dict(hostname="db1", status="online", last_seen_at=_ago(5)))
    _sweep()
    assert _events(env) == [("siem", "event=agent_offline_mass")]
    assert "count=6" in env.events[0]["raw_message"]


def _ids_by_host():
    from sqlalchemy import select

    from worker.database import AsyncSessionLocal
    from worker.models import Agent

    async def go():
        async with AsyncSessionLocal() as s:
            return {h: i for i, h in (await s.execute(select(Agent.id, Agent.hostname))).all()}
    return _run(go())


def test_heartbeating_agents_whose_logs_or_polls_stopped(env):
    from worker.agent_monitor import LAST_LOG_KEY

    now = datetime.now(timezone.utc)
    _agents(
        dict(hostname="muted", status="online", last_seen_at=_ago(10), flow_poll_at=_ago(5)),
        dict(hostname="chatty", status="online", last_seen_at=_ago(10), flow_poll_at=_ago(5)),
        dict(hostname="fake-beats", status="online", last_seen_at=_ago(10), flow_poll_at=_ago(1800)),
        dict(hostname="no-runner", status="online", last_seen_at=_ago(10), flow_poll_at=None),
        dict(hostname="new", status="online", last_seen_at=_ago(10)),  # no log yet: no opinion
    )
    ids = _ids_by_host()
    env.kv[LAST_LOG_KEY.format(ids["muted"])] = str(now.timestamp() - 2 * 3600)
    env.kv[LAST_LOG_KEY.format(ids["chatty"])] = str(now.timestamp() - 60)
    env.kv[LAST_LOG_KEY.format(ids["fake-beats"])] = str(now.timestamp() - 60)
    env.kv[LAST_LOG_KEY.format(ids["no-runner"])] = str(now.timestamp() - 60)

    _sweep()
    assert sorted(_events(env)) == [("fake-beats", "event=agent_heartbeat_anomaly"),
                                    ("muted", "event=agent_logs_silent")], env.events
    muted = next(e for e in env.events if e["hostname"] == "muted")["raw_message"]
    assert "silent_minutes=120" in muted
    assert "kind=no_flow_poll" in next(e for e in env.events if e["hostname"] == "fake-beats")["raw_message"]

    env.events.clear()
    _sweep()
    assert env.events == []  # once per episode

    # logs resume → the flag clears → a later silence reports again
    env.kv[LAST_LOG_KEY.format(ids["muted"])] = str(now.timestamp())
    _sweep()
    env.kv[LAST_LOG_KEY.format(ids["muted"])] = str(now.timestamp() - 2 * 3600)
    _sweep()
    assert _events(env) == [("muted", "event=agent_logs_silent")]


def test_everyone_quiet_at_once_is_not_tampering(env):
    from worker.agent_monitor import LAST_LOG_KEY

    now = datetime.now(timezone.utc)
    _agents(*[dict(hostname=f"web{i}", status="online", last_seen_at=_ago(10), flow_poll_at=_ago(5)) for i in range(6)])
    for agent_id in _ids_by_host().values():
        env.kv[LAST_LOG_KEY.format(agent_id)] = str(now.timestamp() - 3 * 3600)  # e.g. the pipeline was down
    _sweep()
    assert env.events == []
