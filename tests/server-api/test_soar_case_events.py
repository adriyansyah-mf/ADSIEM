"""HTTP case events through the real SOAR engine and PostgreSQL task queue."""
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import anyio
import pytest
from sqlalchemy import select

from app.models.models import AgentTask, Case, CaseAlert, SoarCaseEvent, SoarRun, SoarRunStep
from worker.soar import case_events, case_nodes, engine, nodes
from worker.soar.case_outbox import CaseEvent, enqueue_case_event


@pytest.fixture
async def soar_env(case_env, monkeypatch):
    from worker import settings_cache
    for module in (case_events, case_nodes, engine, nodes, settings_cache):
        monkeypatch.setattr(module, "AsyncSessionLocal", case_env.sessions)
    monkeypatch.setattr(settings_cache, "_cache", {})
    monkeypatch.setattr(settings_cache, "_fetched_at", 0)
    return case_env


def graph(event):
    return {"nodes": [
        {"id": "trigger", "type": "trigger", "params": {"event": event}},
        {"id": "evidence", "type": "case_evidence", "params": {"scope": "case"}},
        {"id": "block", "type": "case_block_ips", "params": {"scope": "event_alert", "duration_seconds": 600}},
    ], "edges": [{"from": "trigger", "output": "main", "to": "evidence"},
                 {"from": "evidence", "output": "main", "to": "block"}]}


async def playbook(env, event):
    response = await env.client.post("/api/soar/playbooks", json={"name": event, "is_enabled": True, "graph": graph(event)})
    assert response.status_code == 201, response.text
    return response.json()


def context(env, alert_id=None):
    return {"trigger": {"case_id": str(env.case.id), "group_id": "blue",
                        "alert_id": str(alert_id) if alert_id else None}, "run": {"id": str(uuid4())}}


async def test_manual_case_creation_drives_a_real_workflow_once(soar_env):
    env = soar_env
    await playbook(env, "case.created")
    response = await env.client.post("/api/cases", json={"title": "Investigate brute force", "alert_id": str(env.alerts[0].id)})
    assert response.status_code == 201, response.text
    assert await case_events.dispatch_case_events() == 1
    assert await case_events.dispatch_case_events() == 0
    async with env.sessions() as db:
        runs = (await db.execute(select(SoarRun))).scalars().all()
    assert len(runs) == 1 and runs[0].trigger_event == "case.created"
    assert await engine.execute_run(runs[0].id) == "success"
    async with env.sessions() as db:
        task = (await db.execute(select(AgentTask))).scalar_one()
        step = (await db.execute(select(SoarRunStep).where(SoarRunStep.node_id == "block"))).scalar_one()
    assert task.params["ip"] == "8.8.8.1" and task.agent_id == env.agents[0].id
    assert task.status == "pending" and step.output_name == "queued"


async def test_accepted_case_evidence_emits_once_and_targets_new_alert(soar_env):
    env = soar_env
    await playbook(env, "case.alert_linked")
    async with env.sessions() as db:
        link = await db.get(CaseAlert, (env.case.id, env.alerts[1].id))
        link.status = "suggested"
        await db.commit()
    path = f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}"
    assert (await env.client.put(path, json={"status": "linked"})).status_code == 200
    assert (await env.client.put(path, json={"status": "linked"})).status_code == 200
    assert await case_events.dispatch_case_events() == 1
    async with env.sessions() as db:
        run = (await db.execute(select(SoarRun))).scalar_one()
    await engine.execute_run(run.id)
    async with env.sessions() as db:
        tasks = (await db.execute(select(AgentTask))).scalars().all()
    assert [(t.agent_id, t.params["ip"]) for t in tasks] == [(env.agents[1].id, "8.8.8.2")]


async def test_event_transaction_rollback_creates_no_runs(soar_env):
    env = soar_env
    await playbook(env, "case.created")
    async with env.sessions() as db:
        await enqueue_case_event(db, CaseEvent(env.case.id, "blue", "case.created"))
        await db.rollback()
    assert await case_events.dispatch_case_events() == 0


async def test_two_consumers_dispatch_one_committed_event_once(soar_env):
    env = soar_env
    await playbook(env, "case.created")
    async with env.sessions() as db:
        await enqueue_case_event(db, CaseEvent(env.case.id, "blue", "case.created", env.alerts[0].id))
        await db.commit()
    async with anyio.create_task_group() as group:
        group.start_soon(case_events.dispatch_case_events)
        group.start_soon(case_events.dispatch_case_events)
    async with env.sessions() as db:
        assert len((await db.execute(select(SoarRun))).scalars().all()) == 1


@pytest.mark.parametrize("status", ["in_review", "escalated", "closed", "resolved"])
async def test_closed_or_worked_case_never_starts_automatic_containment(soar_env, status):
    env = soar_env
    await playbook(env, "case.created")
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.status = status
        await enqueue_case_event(db, CaseEvent(case.id, "blue", "case.created"))
        await db.commit()
    await case_events.dispatch_case_events()
    async with env.sessions() as db:
        assert (await db.execute(select(SoarRun))).scalars().all() == []


async def test_repeated_blocks_preserve_ip_to_host_pairs(soar_env):
    env = soar_env
    node = {"id": "block", "type": "case_block_ips"}
    first = await case_nodes.run_case_node(node, {"scope": "case"}, context(env))
    second = await case_nodes.run_case_node(node, {"scope": "case"}, context(env))
    assert first.data["queued_count"] == 2
    assert second.data["queued_count"] == 0 and second.data["reused_count"] == 2
    async with env.sessions() as db:
        tasks = (await db.execute(select(AgentTask))).scalars().all()
    assert {(t.agent_id, t.params["ip"]) for t in tasks} == {(env.agents[0].id, "8.8.8.1"), (env.agents[1].id, "8.8.8.2")}


@pytest.mark.parametrize("backend,dry_run,reused", [("nft", False, 1), ("noop", False, 0), ("nft", True, 0)])
async def test_only_enforced_unexpired_blocks_are_reused(soar_env, backend, dry_run, reused):
    env = soar_env
    async with env.sessions() as db:
        db.add(AgentTask(agent_id=env.agents[0].id, task_type="block_ip", status="done",
                         params={"ip": "8.8.8.1", "case_id": str(env.case.id), "duration_seconds": 600},
                         result={"backend": backend, "dry_run": dry_run}, completed_at=datetime.now(timezone.utc)))
        await db.commit()
    result = await case_nodes.run_case_node({"id": "b", "type": "case_block_ips"}, {}, context(env, env.alerts[0].id))
    assert result.data["reused_count"] == reused
    assert result.data["queued_count"] == 1 - reused


@pytest.mark.parametrize("invalid", ["foreign_group", "unrelated_ip", "pair_limit", "closed", "offline"])
async def test_invalid_case_block_queues_nothing(soar_env, invalid):
    env = soar_env
    ctx, params = context(env), {"scope": "case"}
    if invalid == "foreign_group":
        ctx["trigger"]["group_id"] = "red"
    if invalid == "unrelated_ip":
        params["ips"] = "1.1.1.1"
    if invalid == "pair_limit":
        params["max_pairs"] = 1
    async with env.sessions() as db:
        if invalid == "closed":
            (await db.get(Case, env.case.id)).status = "closed"
        if invalid == "offline":
            from app.models.models import Agent
            (await db.get(Agent, env.agents[0].id)).status = "offline"
        await db.commit()
    with pytest.raises(nodes.NodeError):
        await case_nodes.run_case_node({"id": "b", "type": "case_block_ips"}, params, ctx)
    async with env.sessions() as db:
        assert (await db.execute(select(AgentTask))).scalars().all() == []


async def test_case_workflow_create_case_reuses_source_without_recursive_events(soar_env):
    env = soar_env
    result = await nodes.run_case({}, {"operation": "create_case"}, context(env))
    assert result.data == {"case_id": str(env.case.id), "created": False}
    async with env.sessions() as db:
        assert (await db.execute(select(SoarCaseEvent))).scalars().all() == []


async def test_manual_run_accepts_case_id_and_refuses_other_group(soar_env):
    env = soar_env
    pb = await playbook(env, "case.created")
    response = await env.client.post(f"/api/soar/playbooks/{pb['id']}/run", json={"case_id": str(env.case.id)})
    assert response.status_code == 202
    async with env.sessions() as db:
        run = await db.get(SoarRun, UUID(response.json()["id"]))
        assert run.context["trigger"]["case_id"] == str(env.case.id)
        foreign = Case(title="Other group", group_id="red")
        db.add(foreign)
        await db.commit()
    denied = await env.client.post(f"/api/soar/playbooks/{pb['id']}/run", json={"case_id": str(foreign.id)})
    assert denied.status_code == 404



async def test_removed_evidence_before_dispatch_does_not_trigger(soar_env):
    env = soar_env
    await playbook(env, "case.alert_linked")
    async with env.sessions() as db:
        await enqueue_case_event(db, CaseEvent(env.case.id, "blue", "case.alert_linked", env.alerts[1].id))
        (await db.get(CaseAlert, (env.case.id, env.alerts[1].id))).status = "detached"
        await db.commit()
    await case_events.dispatch_case_events()
    async with env.sessions() as db:
        assert (await db.execute(select(SoarRun))).scalars().all() == []


async def test_suggestions_are_not_case_evidence_or_block_targets(soar_env):
    env = soar_env
    async with env.sessions() as db:
        (await db.get(CaseAlert, (env.case.id, env.alerts[1].id))).status = "suggested"
        await db.commit()
    result = await case_nodes.run_case_node({"id": "e", "type": "case_evidence"}, {"scope": "case"}, context(env))
    assert result.data["ips"] == ["8.8.8.1"] and result.data["alert_count"] == 1



async def test_failing_event_is_consumed_without_blocking_later_events(soar_env, monkeypatch):
    env = soar_env
    await playbook(env, "case.created")
    async with env.sessions() as db:
        bad = Case(title="Bad", severity="high", status="open", group_id="blue")
        db.add(bad)
        await db.flush()
        await enqueue_case_event(db, CaseEvent(bad.id, "blue", "case.created"))
        await db.commit()
    async with env.sessions() as db:
        await enqueue_case_event(db, CaseEvent(env.case.id, "blue", "case.created", env.alerts[0].id))
        await db.commit()
    real = case_events.read_case_evidence

    async def flaky(db, case):
        if case.id == bad.id:
            raise RuntimeError("boom")
        return await real(db, case)

    monkeypatch.setattr(case_events, "read_case_evidence", flaky)
    assert await case_events.dispatch_case_events() == 2
    assert await case_events.dispatch_case_events() == 0
    async with env.sessions() as db:
        runs = (await db.execute(select(SoarRun))).scalars().all()
    assert [r.context["trigger"]["case_id"] for r in runs] == [str(env.case.id)]
