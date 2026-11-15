"""Alert suppressions (routes/suppressions.py): creating one answers 201 with
created_at as ISO 8601, the same suppression clicked twice stays one row, and
the list works once rows exist. Before, created_at was declared a string, so
the response failed validation (500) after the row was committed and every
retry stored another copy."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import suppressions as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import AlertSuppression


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    evidence_api.user = evidence_api.make_user(perms=("alerts:read", "alerts:manage"))
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _rows(env):
    async with env.sessions() as db:
        return (await db.execute(select(AlertSuppression))).scalars().all()


async def test_create_answers_201_and_a_repeat_stays_one_row(env):
    body = {"entity_type": "ip", "entity_value": " 0.0.0.0 ", "reason": "Confirmed false positive"}
    first = await env.api.post("/api/suppressions", json=body)
    assert first.status_code == 201, first.text
    out = first.json()
    assert out["entity_value"] == "0.0.0.0" and out["group_id"] == "blue" and out["is_active"]
    assert out["created_at"] and "T" in out["created_at"]  # ISO 8601
    for _ in range(2):  # the double and triple click
        again = await env.api.post("/api/suppressions", json=body)
        assert again.status_code == 201 and again.json()["id"] == out["id"]
    assert len(await _rows(env)) == 1

    listed = await env.api.get("/api/suppressions")
    assert listed.status_code == 200, listed.text
    assert [s["id"] for s in listed.json()] == [out["id"]]


async def test_a_removed_suppression_can_be_added_again(env):
    body = {"entity_type": "hostname", "entity_value": "web-01", "reason": "maintenance"}
    first = (await env.api.post("/api/suppressions", json=body)).json()
    assert (await env.api.delete(f"/api/suppressions/{first['id']}")).status_code == 204
    second = await env.api.post("/api/suppressions", json=body)
    assert second.status_code == 201 and second.json()["id"] != first["id"]


async def test_bad_input_is_refused(env):
    assert (await env.api.post("/api/suppressions", json={"entity_type": "port", "entity_value": "22"})).status_code == 400
    assert (await env.api.post("/api/suppressions", json={"entity_type": "ip", "entity_value": "   "})).status_code == 422
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.post("/api/suppressions",
                               json={"entity_type": "ip", "entity_value": "198.51.100.7"})).status_code == 403
