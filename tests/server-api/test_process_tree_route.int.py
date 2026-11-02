# tests/server-api/test_process_tree_route.int.py
"""GET /api/alerts/{id}/process-tree: built from the alert's event and agent,
returns the agent to act on, and stays inside the caller's group."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import alerts
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    event = {"id": "ev1", "agent_id": str(evidence_api.agents["blue"]), "created_at": "2026-11-02T10:00:00+00:00",
             "log_type": "linux_network_connect", "decoded_fields": {"process.pid": "1100", "process.name": "curl"}}
    start = {"id": "x1", "agent_id": str(evidence_api.agents["blue"]), "log_type": "linux_process_exec",
             "created_at": "2026-11-02T09:59:50+00:00",
             "decoded_fields": {"ProcessId": "1100", "ParentProcessId": "0", "Image": "/usr/bin/curl"}}
    seen: list = []

    async def get_log(doc_id):
        return event if doc_id else None

    async def search(query, size=25, sort=None, search_after=None):
        seen.append(query)
        text = str(query)
        return ([start] if "linux_process_exec" in text and "'ProcessId'" in text.replace("decoded_fields.", "'") else
                []), 0, None

    monkeypatch.setattr(alerts, "es_get_log", get_log)
    monkeypatch.setattr(alerts, "es_search", search)
    app = FastAPI()
    app.include_router(alerts.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    evidence_api.seen = seen
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _alert(env, group):
    from uuid import uuid4
    async with env.sessions() as db:
        a = Alert(title="t", severity="high", agent_id=env.agents[group], group_id=group, hostname=f"{group}-host",
                  event_id=uuid4())
        db.add(a)
        await db.commit()
        return a.id


async def test_process_tree_route(api):
    api.user = api.make_user(role="analyst", group="blue", perms=("alerts:read",))
    alert_id = await _alert(api, "blue")
    r = await api.api.get(f"/api/alerts/{alert_id}/process-tree")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["anchor"] == "x1" and body["nodes"][0]["image"] == "/usr/bin/curl"
    assert body["agent"]["hostname"] == "blue-host" and body["agent"]["is_isolated"] is False
    assert all("agent_id" in str(q) for q in api.seen)  # every query is scoped to the alert's agent

    red = await _alert(api, "red")
    assert (await api.api.get(f"/api/alerts/{red}/process-tree")).status_code == 404
    api.user = api.make_user(role="analyst", group="blue", perms=())
    assert (await api.api.get(f"/api/alerts/{alert_id}/process-tree")).status_code == 403
