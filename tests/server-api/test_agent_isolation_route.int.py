# tests/server-api/test_agent_isolation_route.int.py
"""POST/DELETE /api/agents/{id}/isolate answer 200 with the agent (incl. its
log sources) — the change was committed before, but serializing AgentOut
lazy-loaded log_sources in async and turned a successful isolation into a 500."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import agents
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentLogSource, AgentTask


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    async with evidence_api.sessions() as db:
        agent = await db.get(Agent, evidence_api.agents["blue"])
        agent.status = "online"
        db.add(AgentLogSource(agent_id=agent.id, path="/var/log/auth.log", log_type="linux_auth"))
        await db.commit()
    app = FastAPI()
    app.include_router(agents.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _tasks(env):
    async with env.sessions() as db:
        return [t.task_type for t in (await db.execute(select(AgentTask))).scalars()]


async def test_isolate_and_lift_return_the_agent(api):
    api.user = api.make_user(role="analyst", group="blue", perms=("agents:manage",))
    agent_id = api.agents["blue"]

    r = await api.api.post(f"/api/agents/{agent_id}/isolate")
    assert r.status_code == 200, r.text
    assert r.json()["is_isolated"] is True
    assert [s["path"] for s in r.json()["log_sources"]] == ["/var/log/auth.log"]

    r = await api.api.delete(f"/api/agents/{agent_id}/isolate")
    assert r.status_code == 200, r.text
    assert r.json()["is_isolated"] is False
    assert await _tasks(api) == ["isolate_host", "unisolate_host"]


async def test_isolation_stays_in_group(api):
    api.user = api.make_user(role="analyst", group="blue", perms=("agents:manage",))
    red = api.agents["red"]
    assert (await api.api.post(f"/api/agents/{red}/isolate")).status_code == 404
    assert (await api.api.delete(f"/api/agents/{red}/isolate")).status_code == 404
    assert await _tasks(api) == []
