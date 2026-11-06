"""Case evidence and remediation through HTTP over an isolated PostgreSQL schema."""
import os
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes.cases import router
from app.core.database import Base, get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentTask, Alert, Case, CaseAlert, Role, User


@pytest.fixture
async def case_env():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "case_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tables = {model.__table__ for model in (Agent, AgentTask, Alert, Case, CaseAlert, Role, User)}
    tables.add(Base.metadata.tables["case_notes"])
    tables.add(Base.metadata.tables["alert_notes"])
    while True:
        dependencies = {fk.column.table for table in tables for fk in table.foreign_keys}
        if dependencies <= tables:
            break
        tables |= dependencies
    async with engine.begin() as connection:
        await connection.run_sync(lambda connection: Base.metadata.create_all(connection, tables=list(tables)))
    async with sessions() as db:
        role = Role(name="admin")
        db.add(role)
        await db.flush()
        user = User(username="test", email="test@example.com", password_hash="test", role_id=role.id, group_id="blue")
        agents = [Agent(name=f"host{i}", hostname=f"host{i}", group_id=group, token_hash=uuid4().hex)
                  for i, group in enumerate(("blue", "blue", "red"))]
        db.add_all([user, *agents])
        await db.flush()
        alerts = [Alert(title="Brute force", severity="high", group_id=a.group_id, agent_id=a.id,
                        hostname=a.hostname, source_ip=f"8.8.8.{i + 1}") for i, a in enumerate(agents)]
        db.add_all(alerts)
        await db.flush()
        case = Case(title="Distributed brute force", severity="high", status="open", group_id="blue", alert_id=alerts[0].id,
                    ioc_data={"affected_hosts": ["host0", "host1"], "ioc_keys": ["ip:8.8.8.2"]})
        db.add(case)
        await db.flush()
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[1].id, status="linked", method="ai",
                         reason="Same account and service", confidence=0.96, indicators=["ip:8.8.8.2"], accounts=["admin"]))
        await db.commit()
        env = SimpleNamespace(sessions=sessions, case=case, alerts=alerts, agents=agents,
                              user=SimpleNamespace(id=user.id, username="test", group_id="blue",
                                  role=SimpleNamespace(name="admin", permissions=[SimpleNamespace(name=n)
                                      for n in ("cases:manage", "agents:manage")])))
    app = FastAPI()
    app.include_router(router)

    async def database():
        async with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: env.user
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def test_evidence_includes_primary_and_multiple_linked_indicators(case_env):
    env = case_env
    response = await env.client.get(f"/api/cases/{env.case.id}/evidence")
    assert response.status_code == 200
    assert response.json()["blockable_ips"] == ["8.8.8.1", "8.8.8.2"]
    assert {a["id"] for a in response.json()["alerts"]} == {str(a.id) for a in env.alerts[:2]}


async def test_case_list_and_timeline_use_all_linked_alerts(case_env):
    env = case_env
    response = await env.client.get("/api/cases", params={"alert_id": str(env.alerts[1].id), "hostname": "host1"})
    assert response.status_code == 200
    assert response.json()["items"][0]["alert_count"] == 2
    timeline = await env.client.get(f"/api/cases/{env.case.id}/timeline")
    assert timeline.status_code == 200
    assert {i["id"] for i in timeline.json()["items"]} == {str(a.id) for a in env.alerts[:2]}


async def test_multi_host_remediation_retry_is_idempotent(case_env):
    env = case_env
    body = {"request_id": str(uuid4()), "agent_ids": [str(a.id) for a in env.agents[:2]],
            "ips": ["8.8.8.1", "8.8.8.2"], "duration_seconds": 3600}
    first = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    second = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    assert first.status_code == second.status_code == 201
    assert len(first.json()) == 4
    assert {t["id"] for t in first.json()} == {t["id"] for t in second.json()}
    assert {t["status"] for t in first.json()} == {"pending"}
    async with env.sessions() as db:
        assert len((await db.execute(select(AgentTask))).scalars().all()) == 4


@pytest.mark.parametrize("invalid", ["foreign_agent", "unknown_ip", "invalid_ip", "invalid_duration"])
async def test_invalid_remediation_enqueues_nothing(case_env, invalid):
    env = case_env
    body = {"request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"], "duration_seconds": 3600}
    if invalid == "foreign_agent":
        body["agent_ids"] = [str(env.agents[2].id)]
    if invalid == "unknown_ip":
        body["ips"] = ["1.1.1.1"]
    if invalid == "invalid_ip":
        body["ips"] = ["example.com;whoami"]
    if invalid == "invalid_duration":
        body["duration_seconds"] = -1
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    assert response.status_code == 422
    async with env.sessions() as db:
        assert (await db.execute(select(AgentTask))).scalars().all() == []


async def test_detach_keeps_alert_and_removes_it_from_remediation(case_env):
    env = case_env
    response = await env.client.put(f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}", json={"status": "detached"})
    assert response.status_code == 200
    evidence = (await env.client.get(f"/api/cases/{env.case.id}/evidence")).json()
    assert evidence["blockable_ips"] == ["8.8.8.1"]
    assert next(a for a in evidence["alerts"] if a["id"] == str(env.alerts[1].id))["status"] == "detached"
    async with env.sessions() as db:
        assert await db.get(Alert, env.alerts[1].id) is not None


@pytest.mark.parametrize("status", ["in_review", "escalated", "resolved", "closed"])
async def test_non_open_case_rejects_membership_changes(case_env, status):
    env = case_env
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.status = status
        await db.commit()
    response = await env.client.put(f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}", json={"status": "detached"})
    assert response.status_code == 409


async def test_other_group_cannot_read_case_or_queue_remediation(case_env):
    env = case_env
    env.user.group_id = "red"
    assert (await env.client.get(f"/api/cases/{env.case.id}/evidence")).status_code == 404
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json={
        "request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"],
    })
    assert response.status_code == 404


async def test_viewer_cannot_queue_remediation(case_env):
    env = case_env
    env.user.role = SimpleNamespace(name="viewer", permissions=[])
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json={
        "request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"],
    })
    assert response.status_code == 403
