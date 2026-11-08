# tests/server-api/test_web_block_health.int.py
"""Agents report Web Protection health in the heartbeat: stored with the
server's receipt time, invalid objects dropped, and listed per group."""
import asyncio
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import web_protection as routes
from app.core.database import get_db
from app.core.deps import get_current_user

HEALTH = {"enabled": True, "entries": 12, "version": "blue:7", "group": "blue", "ca_installed": True,
          "ca_fingerprint": "ab" * 32, "page_server": "ok", "hosts_tampered": False, "last_error": ""}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    evidence_api.user = evidence_api.make_user(perms=("alerts:read",))
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


def beat(agent_id, health=None):
    body = {"agent_id": str(agent_id), "status": "online", "version": "1.9.0"}
    if health is not None:
        body["web_block_health"] = health
    return body


def test_invalid_health_is_dropped_not_the_heartbeat():
    from app.schemas.schemas import HeartbeatRequest
    ok = HeartbeatRequest(agent_id=uuid4(), web_block_health={**HEALTH, "future": 1})
    assert ok.web_block_health.entries == 12
    for bad in ({**HEALTH, "entries": "many"}, "nope"):
        assert HeartbeatRequest(agent_id=uuid4(), web_block_health=bad).web_block_health is None
    long = HeartbeatRequest(agent_id=uuid4(), web_block_health={**HEALTH, "last_error": "x" * 301})
    assert long.web_block_health.last_error == "x" * 300 and long.web_block_health.entries == 12


async def test_heartbeat_stores_health_and_endpoint_lists_it(env):
    blue = env.agents["blue"]
    r = await env.client.post("/api/ingest/heartbeat", json=beat(blue, HEALTH), headers={"X-Agent-Token": "blue-token"})
    assert r.status_code == 200, r.text
    r = await env.api.get("/api/web-blocks/agents")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert [i["agent_id"] for i in items] == [str(blue)]
    assert items[0]["health"]["entries"] == 12 and items[0]["health_at"] and items[0]["group_id"] == "blue"
    assert items[0]["online"] is True


async def test_invalid_health_keeps_last_snapshot(env):
    blue = env.agents["blue"]
    h = {"X-Agent-Token": "blue-token"}
    await env.client.post("/api/ingest/heartbeat", json=beat(blue, HEALTH), headers=h)
    r = await env.client.post("/api/ingest/heartbeat", json=beat(blue, {**HEALTH, "entries": "x"}), headers=h)
    assert r.status_code == 200
    items = (await env.api.get("/api/web-blocks/agents")).json()["items"]
    assert items[0]["health"]["entries"] == 12


async def test_no_report_means_null_health_and_scope(env):
    red = env.agents["red"]
    items = (await env.api.get("/api/web-blocks/agents")).json()["items"]
    assert [i["group_id"] for i in items] == ["blue"] and items[0]["health"] is None and items[0]["health_at"] is None
    assert str(red) not in [i["agent_id"] for i in items]
    env.user = env.make_user(role="superadmin", group="default", perms=())
    items = (await env.api.get("/api/web-blocks/agents")).json()["items"]
    assert {i["group_id"] for i in items} == {"blue", "red"}


async def test_long_last_error_is_truncated_and_health_kept(env):
    blue = env.agents["blue"]
    health = {**HEALTH, "last_error": "e" * 1000, "page_server": "page_unavailable: " + "p" * 500}
    r = await env.client.post("/api/ingest/heartbeat", json=beat(blue, health), headers={"X-Agent-Token": "blue-token"})
    assert r.status_code == 200, r.text
    items = (await env.api.get("/api/web-blocks/agents")).json()["items"]
    stored = items[0]["health"]
    assert stored["last_error"] == "e" * 300
    assert len(stored["page_server"]) == 300 and stored["page_server"].startswith("page_unavailable: ")
    assert stored["entries"] == 12 and stored["ca_installed"] is True and stored["version"] == "blue:7"
