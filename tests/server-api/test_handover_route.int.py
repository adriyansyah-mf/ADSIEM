# tests/server-api/test_handover_route.int.py
"""POST and GET /api/handover answer with the handover, created_at included.
created_at was typed str while the row holds a datetime, so every response
failed validation (500) after the handover had been saved."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import handover
from app.core.database import get_db
from app.core.deps import get_current_user


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
    app.include_router(handover.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def test_create_and_list_handover(api):
    api.user = api.make_user(role="analyst", group="blue", perms=("alerts:read",))
    r = await api.api.post("/api/handover", json={"shift_label": "night", "summary": "quiet shift", "notes": "watch host1"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["group_id"] == "blue" and body["shift_label"] == "night"
    assert body["summary"].startswith("quiet shift") and "watch host1" in body["summary"]
    assert body["created_at"]  # ISO timestamp

    r = await api.api.get("/api/handover?limit=20")
    assert r.status_code == 200, r.text
    assert [h["id"] for h in r.json()] == [body["id"]]


async def test_superadmin_without_group_uses_default(api):
    api.user = api.make_user(role="superadmin", group=None, perms=("alerts:read",))
    r = await api.api.post("/api/handover", json={"summary": "all groups"})
    assert r.status_code == 201, r.text
    assert r.json()["group_id"] == "default"
