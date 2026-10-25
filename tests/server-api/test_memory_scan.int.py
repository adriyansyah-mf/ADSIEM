# tests/server-api/test_memory_scan.int.py
"""Memory scans: the dashboard's memory_scan task carries the enabled YARA
rules, and the Memory artifacts compile with the rules injected."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import yara_rules
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import models
from app.services import flow_artifacts


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
    app.include_router(yara_rules.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def test_memory_scan_task_carries_rules(api):
    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    blue = str(api.agents["blue"])
    r = await api.api.post("/api/yara-rules/scan-memory", json={"agent_id": blue, "pid": 1234})
    assert r.status_code == 400  # no rules yet
    async with api.sessions() as db:
        db.add(models.YaraRule(name="cs_beacon", content="rule b { strings: $a = \"x\" condition: $a }"))
        db.add(models.YaraRule(name="off", content="rule o { condition: true }", is_enabled=False))
        await db.commit()
    r = await api.api.post("/api/yara-rules/scan-memory", json={"agent_id": blue, "pid": 1234})
    assert r.status_code == 201, r.text
    task = r.json()
    assert task["task_type"] == "memory_scan"
    async with api.sessions() as db:
        row = await db.get(models.AgentTask, task["id"])
        assert row.params["pid"] == 1234
        assert [x["name"] for x in row.params["rules"]] == ["cs_beacon"]
    assert (await api.api.post("/api/yara-rules/scan-memory", json={"agent_id": blue, "pid": -1})).status_code == 422


async def test_memory_scan_respects_groups_and_permissions(api):
    red = str(api.agents["red"])
    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    assert (await api.api.post("/api/yara-rules/scan-memory", json={"agent_id": red})).status_code == 404
    api.user = api.make_user(role="analyst", group="blue", perms=("agents:read",))
    blue = str(api.agents["blue"])
    assert (await api.api.post("/api/yara-rules/scan-memory", json={"agent_id": blue})).status_code == 403


def test_memory_artifacts_get_rules_injected():
    arts = flow_artifacts.builtin_artifacts()
    art = arts["Linux.Memory.Yara"]
    params = flow_artifacts.resolve_params(art, {"Pid": 42, "AnonOnly": True})
    req = flow_artifacts.compile_request(art, "f1", params, 60, 100,
                                         yara_rules=[{"name": "r", "content": "rule r { condition: true }"}])
    src = req["sources"][0]
    assert src["plugin"] == "memyara"
    assert src["args"]["pid"] == 42 and src["args"]["anon_only"] is True
    assert src["args"]["rules"][0]["name"] == "r"
    assert "Windows.Memory.RWX" in arts and arts["Windows.Memory.RWX"].sources[0].plugin == "memrwx"
