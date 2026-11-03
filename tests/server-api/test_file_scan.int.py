# tests/server-api/test_file_scan.int.py
"""POST /api/agents/{id}/file-scan queues a file_scan task for the agent,
within the caller's group; the policy's scan schedules are validated."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import select

from app.api.routes import agents
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import AgentTask
from app.services import agent_policy


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(agents.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def test_file_scan_task(api):
    c = api.api
    api.user = api.make_user(role="analyst", group="blue", perms=("agents:manage",))
    blue, red = api.agents["blue"], api.agents["red"]
    r = await c.post(f"/api/agents/{blue}/file-scan", json={"kind": "full"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["task_type"] == "file_scan" and body["params"] == {"kind": "full", "paths": []}
    r = await c.post(f"/api/agents/{blue}/file-scan", json={"kind": "custom", "paths": [" /srv/upload ", ""]})
    assert r.status_code == 201 and r.json()["params"]["paths"] == ["/srv/upload"]
    assert (await c.post(f"/api/agents/{blue}/file-scan", json={"kind": "custom"})).status_code == 400
    assert (await c.post(f"/api/agents/{blue}/file-scan", json={"kind": "deep"})).status_code == 422
    assert (await c.post(f"/api/agents/{red}/file-scan", json={})).status_code == 404  # other group
    async with api.sessions() as db:
        tasks = (await db.execute(select(AgentTask).where(AgentTask.task_type == "file_scan"))).scalars().all()
    assert len(tasks) == 2 and all(t.agent_id == blue for t in tasks)


def test_scan_schedules_validated():
    p = agent_policy.PolicySettings.model_validate({"quick_scan_time": "12:30", "full_scan_schedule": " Sun  02:00 "})
    assert p.quick_scan_time == "12:30" and p.full_scan_schedule == "sun 02:00"
    assert agent_policy.PolicySettings.model_validate({}).quick_scan_time == ""
    for bad in ({"quick_scan_time": "24:00"}, {"quick_scan_time": "noon"}, {"full_scan_schedule": "sunday 02:00"},
                {"full_scan_schedule": "02:00"}):
        with pytest.raises(ValidationError):
            agent_policy.PolicySettings.model_validate(bad)
