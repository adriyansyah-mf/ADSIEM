# tests/server-api/test_entity_risk_api.int.py
"""/api/entity-risk: riskiest entities with the 24 h decay applied at read
time, group scoping, and the detail view with the contributing alerts."""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import entity_risk
from app.core.database import Base, get_db
from app.core.deps import get_current_user
from app.models.models import EntityRisk


@pytest.fixture(autouse=True)
def _loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def user(group="blue", role="analyst"):
    return SimpleNamespace(id=uuid4(), group_id=group, username=role,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name="alerts:read")]))


@pytest.fixture
async def env():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "risk_api_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[EntityRisk.__table__]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    state = SimpleNamespace(user=user(), sessions=sessions)

    async def database():
        async with sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(entity_risk.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: state.user
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            state.client = client
            yield state
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def add(env, entity_type, value, group, score, hours_ago=0.0):
    now = datetime.now(timezone.utc)
    async with env.sessions() as db:
        db.add(EntityRisk(entity_type=entity_type, entity_value=value, group_id=group, risk_score=score,
                          peak_score=score, alert_count=3, sources={"ioa": 2, "sigma": 1},
                          tactics={"execution": now.timestamp(), "persistence": (now - timedelta(days=3)).timestamp()},
                          recent=[{"title": "IOA: web server shell", "severity": "high"}],
                          updated_at=now - timedelta(hours=hours_ago)))
        await db.commit()


async def test_riskiest_first_with_decay_and_group_scope(env):
    await add(env, "host", "web-01", "blue", 80, hours_ago=24)   # decays to 40
    await add(env, "host", "db-01", "blue", 60)
    await add(env, "user", "alice", "blue", 30)
    await add(env, "host", "red-01", "red", 99)
    items = (await env.client.get("/api/entity-risk")).json()["items"]
    assert [(i["entity_value"], round(i["risk_score"])) for i in items] == [("db-01", 60), ("web-01", 40), ("alice", 30)]
    assert items[0]["tactics"] == ["execution"]  # persistence was 3 days ago
    assert items[0]["top_alert"] == "IOA: web server shell"
    hosts = (await env.client.get("/api/entity-risk", params={"entity_type": "host", "min_risk": 50})).json()["items"]
    assert [i["entity_value"] for i in hosts] == ["db-01"]
    detail = (await env.client.get("/api/entity-risk/host/db-01")).json()
    assert detail["recent"][0]["severity"] == "high" and detail["sources"] == {"ioa": 2, "sigma": 1}
    assert (await env.client.get("/api/entity-risk/host/red-01")).status_code == 404  # another group's
    env.user = user(group=None, role="superadmin")
    env.user.role.name = "superadmin"
    assert "red-01" in [i["entity_value"] for i in (await env.client.get("/api/entity-risk")).json()["items"]]
