# tests/server-api/test_lateral_api.int.py
"""/api/lateral/graph: nodes (agents vs bare addresses), edges in the window,
new paths, focus on one host, group scoping."""
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

from app.api.routes import lateral
from app.core.database import Base, get_db
from app.core.deps import get_current_user
from app.core.security import hash_token
from app.models.models import Agent, LateralEdge


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
    schema = "lateral_api_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {Agent.__table__, LateralEdge.__table__}
    while True:
        deps = {fk.column.table for t in tables for fk in t.foreign_keys}
        if deps <= tables:
            break
        tables |= deps
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=list(tables)))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    state = SimpleNamespace(user=user(), sessions=sessions)

    async def database():
        async with sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(lateral.router)
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


async def test_graph(env):
    now = datetime.now(timezone.utc)
    async with env.sessions() as db:
        for h in ("web-01", "db-01"):
            db.add(Agent(name=h, hostname=h, group_id="blue", token_hash=hash_token(h), approved=True, status="online"))
        db.add_all([
            LateralEdge(group_id="blue", src="web-01", dst="db-01", protocol="ssh", users=["deploy"], count=40,
                        first_seen=now - timedelta(days=20), last_seen=now - timedelta(minutes=5)),
            LateralEdge(group_id="blue", src="db-01", dst="10.0.0.99", protocol="smb", users=[], count=1,
                        first_seen=now - timedelta(hours=1), last_seen=now - timedelta(hours=1)),
            LateralEdge(group_id="blue", src="old-01", dst="web-01", protocol="rdp", users=["x"], count=1,
                        first_seen=now - timedelta(days=9), last_seen=now - timedelta(days=9)),
            LateralEdge(group_id="red", src="r1", dst="r2", protocol="ssh", users=[], count=1,
                        first_seen=now, last_seen=now),
        ])
        await db.commit()
    g = (await env.client.get("/api/lateral/graph")).json()
    assert {(e["src"], e["dst"], e["new"]) for e in g["edges"]} == {("web-01", "db-01", False), ("db-01", "10.0.0.99", True)}
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes["web-01"]["agent"] and not nodes["10.0.0.99"]["agent"] and nodes["db-01"]["in"] == 1
    new_only = (await env.client.get("/api/lateral/graph", params={"new_only": True})).json()
    assert [e["dst"] for e in new_only["edges"]] == ["10.0.0.99"]
    week = (await env.client.get("/api/lateral/graph", params={"hours": 24 * 10, "host": "web-01"})).json()
    assert {(e["src"], e["dst"]) for e in week["edges"]} == {("web-01", "db-01"), ("old-01", "web-01")}
