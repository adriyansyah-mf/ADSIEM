# tests/worker/test_entity_risk.int.py
"""Entity risk DB writes (worker/worker/entity_risk.py) against a disposable
PostgreSQL schema: rows per host and user, one [Risk] alert per day, and risk
alerts never feeding themselves."""
import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import EntityRisk
from worker import entity_risk as er


@pytest.fixture(autouse=True)
def _loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def risk(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "risk_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[EntityRisk.__table__]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    raised = []

    async def fake_raise(entity_type, value, state, group_id, agent_id, hostname, now):
        raised.append((entity_type, value, state["risk_score"], er.active_tactics(state, now)))

    async def setting(key, default=""):
        return default

    monkeypatch.setattr(er, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(er, "_raise", fake_raise)
    monkeypatch.setattr(er.settings_cache, "get_setting", setting)
    try:
        yield sessions, raised
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def alert(level, tags, host="web-01", user=None, rid="rule-x", title="t"):
    return await er.record(alert_id=uuid4(), rule_match={"id": rid, "title": title, "level": level, "tags": tags},
                           techniques=[], group_id="blue", hostname=host, user=user)


async def test_alerts_accumulate_per_host_and_user_and_raise_once(risk):
    sessions, raised = risk
    assert await alert("high", ["attack.execution"], user="alice", rid="rule-ioa-webserver-shell",
                       title="IOA: web server shell") == []
    assert await alert("medium", ["attack.discovery"], rid="rule-behavior-rare-parent-child") == []
    # high + execution (40), medium + discovery (25): 65, then C2 pushes the host over 70 with 3 tactics
    assert await alert("high", ["attack.command_and_control"], rid="rule-behavior-beaconing") == ["web-01"]
    async with sessions() as db:
        rows = {(r.entity_type, r.entity_value): r for r in (await db.execute(select(EntityRisk))).scalars()}
    host = rows[("host", "web-01")]
    assert host.alert_count == 3 and host.risk_score == 100 and host.risk_alert_at is not None
    assert host.sources == {"ioa": 1, "behavior": 2} and host.recent[0]["title"] == "t"
    assert rows[("user", "alice")].risk_score == 40
    assert raised == [("host", "web-01", 100, ["command_and_control", "discovery", "execution"])]
    # more alerts the same day: no second risk alert
    assert await alert("critical", ["attack.impact"]) == []


async def test_risk_alerts_do_not_feed_themselves(risk):
    sessions, _ = risk
    assert await alert("critical", ["attack.execution"], rid=er.RULE_ID) == []
    async with sessions() as db:
        assert (await db.execute(select(EntityRisk))).scalars().all() == []
