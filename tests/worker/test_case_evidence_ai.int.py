# tests/worker/test_case_evidence_ai.int.py
"""The worker half of case evidence: correlation decisions and campaign joins
write case_alerts that the case-evidence API then exposes.

These live under tests/worker — not tests/server-api — because they import the
worker's llm_gateway, which registers the same siem_llm_* Prometheus metrics as
the server-api's gateway. CI runs the suites in separate processes (see
.github/workflows/ci.yml); one interpreter cannot own both registries.

Needs TEST_DATABASE_URL naming a disposable PostgreSQL; every test gets its
own schema, dropped afterwards (never the public schema)."""
import os
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes.cases import router
from app.api.routes.soar import router as soar_router
from app.core.database import Base, get_db
from app.core.deps import get_current_user
from app.models.models import Agent, Alert, Case, CaseAlert, Role, User


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
    tables = {model.__table__ for model in (Agent, Alert, Case, CaseAlert, Role, User)}
    tables.add(Base.metadata.tables["case_notes"])
    tables.add(Base.metadata.tables["alert_notes"])
    # case writes enqueue SOAR case events in the same transaction
    tables.update(Base.metadata.tables[name] for name in (
        "soar_case_events", "soar_playbooks", "soar_actions", "soar_playbook_runs", "soar_playbook_run_steps",
        "platform_settings", "audit_logs",
    ))
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
    app.include_router(soar_router)

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


async def test_ai_groups_different_ips_with_evidence_and_keeps_provenance(case_env, monkeypatch):
    from worker import case_correlation as correlation
    from worker.llm_gateway import Completion
    env = case_env
    monkeypatch.setattr(correlation, "AsyncSessionLocal", env.sessions)

    async def completion(messages, **kwargs):
        return Completion(text='{"action":"join","case_id":"' + str(env.case.id) +
                          '","confidence":0.96,"reason":"Same admin account and target; distributed brute force."}')

    monkeypatch.setattr(correlation, "complete", completion)
    incoming = correlation.CorrelationInput(alert_id=env.alerts[0].id, group_id="blue", title="Brute force",
                                           hostname="host0", keys=["ip:8.8.8.1"], accounts=["admin"])
    decision = await correlation.choose_case(incoming)
    assert decision.action == "join"
    assert await correlation.record_link(incoming, decision)
    evidence = (await env.client.get(f"/api/cases/{env.case.id}/evidence")).json()
    alert = next(a for a in evidence["alerts"] if a["id"] == str(incoming.alert_id))
    assert alert["method"] == "ai" and alert["confidence"] == 0.96
    assert alert["accounts"] == ["admin"]


@pytest.mark.parametrize("status", ["in_review", "escalated", "resolved", "closed"])
async def test_ai_cannot_choose_or_write_to_non_open_case(case_env, monkeypatch, status):
    from worker import case_correlation as correlation
    env = case_env
    monkeypatch.setattr(correlation, "AsyncSessionLocal", env.sessions)
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.status = status
        await db.commit()
    incoming = correlation.CorrelationInput(alert_id=env.alerts[0].id, group_id="blue", title="Brute force",
                                           hostname="host0", keys=["ip:8.8.8.1"])
    assert (await correlation.choose_case(incoming)).action == "new"
    assert not await correlation.record_link(incoming, correlation.Decision(action="join", case_id=env.case.id, confidence=1))


async def test_ai_cannot_attach_foreign_group_alert(case_env, monkeypatch):
    from worker import case_correlation as correlation
    env = case_env
    monkeypatch.setattr(correlation, "AsyncSessionLocal", env.sessions)
    incoming = correlation.CorrelationInput(alert_id=env.alerts[2].id, group_id="blue", title="Brute force",
                                           hostname="host0", keys=["ip:8.8.8.1"])
    assert (await correlation.choose_case(incoming)).action == "new"
    assert not await correlation.record_link(incoming, correlation.Decision(action="join", case_id=env.case.id, confidence=1))


async def test_ai_failure_falls_back_without_host_only_join(case_env, monkeypatch):
    from worker import case_correlation as correlation
    from worker.llm_gateway import LLMError
    env = case_env
    monkeypatch.setattr(correlation, "AsyncSessionLocal", env.sessions)

    async def unavailable(messages, **kwargs):
        raise LLMError("test provider outage")

    monkeypatch.setattr(correlation, "complete", unavailable)
    incoming = correlation.CorrelationInput(alert_id=env.alerts[0].id, group_id="blue", title="Brute force",
                                           hostname="host0", keys=["ip:1.1.1.1"])
    decision = await correlation.choose_case(incoming)
    assert decision.action == "new" and decision.method == "fallback"


async def test_ai_cannot_restore_analyst_detached_alert(case_env, monkeypatch):
    from worker import case_correlation as correlation
    env = case_env
    monkeypatch.setattr(correlation, "AsyncSessionLocal", env.sessions)
    await env.client.put(f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}", json={"status": "detached"})
    incoming = correlation.CorrelationInput(alert_id=env.alerts[1].id, group_id="blue", title="Brute force",
                                           hostname="host1", keys=["ip:8.8.8.2"])
    assert (await correlation.choose_case(incoming)).action == "new"
    assert not await correlation.record_link(incoming, correlation.Decision(action="join", case_id=env.case.id, confidence=1))


async def test_campaign_join_preserves_indicators_and_escalates_same_open_case(case_env, monkeypatch):
    from worker import ai_analyst
    env = case_env
    monkeypatch.setattr(ai_analyst, "AsyncSessionLocal", env.sessions)
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.ioc_data = {**case.ioc_data, "attack_family": "initial_access", "families_seen": ["initial_access"]}
        await db.commit()
    result = await ai_analyst._join_campaign_case(
        case_id=str(env.case.id), alert_id=str(env.alerts[1].id), title="Persistence detected",
        triage_notes="Login followed by persistence on the same host", severity="high", family="persistence",
        keys=["hash:" + "a" * 64], hostname="host1",
    )
    assert result["escalated"]
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        assert case.status == "open" and case.severity == "critical"
        assert set(case.ioc_data["ioc_keys"]) == {"ip:8.8.8.2", "hash:" + "a" * 64}
        assert case.ai_reasoning == "Login followed by persistence on the same host"


async def test_join_refuses_case_closed_since_selection(case_env, monkeypatch):
    from worker import ai_analyst
    env = case_env
    monkeypatch.setattr(ai_analyst, "AsyncSessionLocal", env.sessions)
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.status = "closed"
        await db.commit()
    result = await ai_analyst._join_campaign_case(
        case_id=str(env.case.id), alert_id=str(env.alerts[1].id), title="Persistence detected",
        triage_notes="Should not update", severity="critical", family="persistence", keys=["ip:1.1.1.1"], hostname="host1",
    )
    assert result == {"escalated": False, "new_host": False}
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        assert case.status == "closed" and case.severity == "high" and case.ai_reasoning is None


# ── SOAR case events emitted by the worker (moved here for the metrics-registry reason above)

async def _case_playbook(env, monkeypatch, event):
    from worker import settings_cache
    from worker.soar import case_events, engine
    for module in (case_events, engine, settings_cache):
        monkeypatch.setattr(module, "AsyncSessionLocal", env.sessions)
    monkeypatch.setattr(settings_cache, "_cache", {})
    monkeypatch.setattr(settings_cache, "_fetched_at", 0)
    graph = {"nodes": [{"id": "trigger", "type": "trigger", "params": {"event": event}}], "edges": []}
    response = await env.client.post("/api/soar/playbooks", json={"name": event, "is_enabled": True, "graph": graph})
    assert response.status_code == 201, response.text
    return case_events


async def test_ai_link_event_waits_for_final_case_update_and_survives_retry(case_env, monkeypatch):
    from app.models.models import SoarCaseEvent, SoarRun
    from worker import ai_analyst, case_correlation
    env = case_env
    monkeypatch.setattr(case_correlation, "AsyncSessionLocal", env.sessions)
    monkeypatch.setattr(ai_analyst, "AsyncSessionLocal", env.sessions)
    case_events = await _case_playbook(env, monkeypatch, "case.alert_linked")
    async with env.sessions() as db:
        (await db.get(CaseAlert, (env.case.id, env.alerts[1].id))).status = "suggested"
        await db.commit()
    incoming = case_correlation.CorrelationInput(alert_id=env.alerts[1].id, group_id="blue",
                                                 title="Persistence", hostname="host1", keys=["ip:8.8.8.2"])
    decision = case_correlation.Decision(action="join", case_id=env.case.id, confidence=0.95)
    assert await case_correlation.record_link(incoming, decision, emit_event=False)
    async with env.sessions() as db:
        pending = (await db.execute(select(SoarCaseEvent))).scalar_one()
        assert pending.ready is False and pending.processed_at is None
    assert await case_events.dispatch_case_events() == 0
    # Retrying the already-persisted association must preserve the pending event.
    assert await case_correlation.record_link(incoming, decision, emit_event=False)
    await ai_analyst._join_campaign_case(case_id=str(env.case.id), alert_id=str(env.alerts[1].id),
        title="Persistence", triage_notes="Updated evidence", severity="critical", family="persistence",
        keys=["ip:8.8.8.2"], hostname="host1")
    assert await case_events.dispatch_case_events() == 1
    async with env.sessions() as db:
        run = (await db.execute(select(SoarRun))).scalar_one()
        assert run.context["trigger"]["severity"] == "critical"


async def test_ai_created_case_emits_creation_event(case_env, monkeypatch):
    from app.models.models import SoarRun
    from worker import ai_analyst
    env = case_env
    monkeypatch.setattr(ai_analyst, "AsyncSessionLocal", env.sessions)
    case_events = await _case_playbook(env, monkeypatch, "case.created")
    cid = await ai_analyst._create_case_from_verdict(
        alert_id=str(env.alerts[0].id), title="Brute force", severity="high", verdict="create_case",
        analysis={"triage_notes": "Suspicious activity", "confidence": 0.95}, enrichment=None,
        group_id="blue", hostname="host0", keys=["ip:8.8.8.1"],
    )
    assert await case_events.dispatch_case_events() == 1
    async with env.sessions() as db:
        run = (await db.execute(select(SoarRun))).scalar_one()
    assert run.context["trigger"]["case_id"] == cid and run.context["trigger"]["created_by_ai"]
