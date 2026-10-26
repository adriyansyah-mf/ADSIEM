# tests/server-api/test_prevention_rules.int.py
"""Execution prevention rules: operators manage them, approved agents
fetch the enabled set and skip the download when it has not changed."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import prevention_rules
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import models

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    # pytest-asyncio 0.24 runs the test on the *current* loop; modules run
    # earlier in the session can leave none.
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(prevention_rules.router)
    app.include_router(prevention_rules.agent_router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    prevention_rules.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


def admin(env):
    return env.make_user(role="admin", perms=("rules:create", "rules:update", "rules:delete"))


async def test_operator_crud_and_validation(api):
    api.user = admin(api)
    c = api.api
    r = await c.post("/api/prevention-rules", json={"name": "no tmp", "rule_type": "dir", "value": "/tmp"})
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["action"] == "detect"  # never blocks unless asked to
    for bad in (
        {"name": "h", "rule_type": "hash", "value": "abc"},
        {"name": "p", "rule_type": "path", "value": "relative/x"},
        {"name": "w", "rule_type": "parent", "value": "sh", "parent": ""},
        {"name": "n", "rule_type": "parent", "value": "/bin/sh", "parent": "nginx"},
        {"name": "a", "rule_type": "dir", "value": "/tmp", "action": "kill"},
    ):
        assert (await c.post("/api/prevention-rules", json=bad)).status_code == 422, bad
    assert (await c.post("/api/prevention-rules", json={"name": "no tmp", "rule_type": "dir", "value": "/var/tmp"})).status_code == 409
    h = await c.post("/api/prevention-rules", json={"name": "bad", "rule_type": "hash", "value": "AB" * 32, "action": "block"})
    assert h.json()["value"] == "ab" * 32
    r = await c.put(f"/api/prevention-rules/{rule['id']}", json={"name": "no tmp", "rule_type": "dir", "value": "/tmp", "action": "block"})
    assert r.json()["action"] == "block"
    assert (await c.patch(f"/api/prevention-rules/{rule['id']}/toggle")).json()["is_enabled"] is False
    assert len((await c.get("/api/prevention-rules")).json()) == 2
    assert (await c.delete(f"/api/prevention-rules/{rule['id']}")).status_code == 204


async def test_analyst_cannot_change_rules(api):
    r = await api.api.post("/api/prevention-rules", json={"name": "x", "rule_type": "dir", "value": "/tmp"})
    assert r.status_code == 403


async def test_agent_fetch_and_unchanged(api):
    c = api.api
    r = await c.post("/api/ingest/prevention-rules", json={}, headers=BLUE)
    assert r.json() == {"hash": "", "unchanged": False, "rules": []}
    async with api.sessions() as db:
        db.add(models.ExecPreventionRule(name="web shell", rule_type="parent", value="sh,bash", parent="nginx", action="block"))
        db.add(models.ExecPreventionRule(name="off", rule_type="dir", value="/x", is_enabled=False))
        await db.commit()
    prevention_rules.invalidate()
    body = (await c.post("/api/ingest/prevention-rules", json={"loaded_hash": ""}, headers=BLUE)).json()
    assert body["hash"] and not body["unchanged"]
    assert [(x["name"], x["rule_type"], x["parent"], x["action"]) for x in body["rules"]] == [("web shell", "parent", "nginx", "block")]
    again = (await c.post("/api/ingest/prevention-rules", json={"loaded_hash": body["hash"]}, headers=BLUE)).json()
    assert again == {"hash": body["hash"], "unchanged": True, "rules": []}


async def test_agent_must_be_approved(api):
    c = api.api
    assert (await c.post("/api/ingest/prevention-rules", json={}, headers={"X-Agent-Token": "nope"})).status_code in (401, 403)
    async with api.sessions() as db:
        a = await db.get(models.Agent, api.agents["blue"])
        a.approved = False
        await db.commit()
    assert (await c.post("/api/ingest/prevention-rules", json={}, headers=BLUE)).status_code == 403
