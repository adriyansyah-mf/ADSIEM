# tests/worker/test_soar_engine.int.py
"""SOAR workflow engine against a real Postgres: event matching, branching,
error edges, retry, approval wait/resume/timeout, secrets redaction, and the
legacy-playbook conversion. Outbound HTTP is replaced by a fake.

Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture()
def db(monkeypatch):
    from sqlalchemy import text

    from worker import settings_cache
    from worker.database import engine
    from worker.models import Base
    from worker.soar import nodes

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
            # created by server-api in production
            await conn.execute(text("CREATE TABLE platform_settings (key VARCHAR(100) PRIMARY KEY, value TEXT)"))
    _run(setup())
    settings_cache._cache, settings_cache._fetched_at = {}, 0.0

    async def no_guard(url, allowlist=""):
        return None
    monkeypatch.setattr(nodes, "check_target", no_guard)
    yield
    _run(engine.dispose())


class FakeHTTP:
    """Stands in for nodes._send: scripted responses, records every call."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    async def __call__(self, method, url, **kw):
        from worker.soar.nodes import NodeError
        self.calls.append({"method": method, "url": url, **kw})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        if isinstance(r, int):
            raise NodeError(f"HTTP {r}", {"status": r, "ok": False, "body": "", "headers": {}})
        return {"status": 200, "ok": True, "headers": {}, "body": r, "truncated": False, "elapsed_ms": 1}


def _add(*objs):
    from worker.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as s:
            for o in objs:
                s.add(o)
            await s.commit()
    _run(go())


def _alert_and_agent(group="blue", hostname="web01"):
    from worker.models import Agent, Alert
    agent = Agent(id=uuid.uuid4(), hostname=hostname, group_id=group, status="online",
                  last_seen_at=datetime.now(timezone.utc))
    alert = Alert(id=uuid.uuid4(), title="Successful Login After Brute Force", severity="critical",
                  group_id=group, source_ip="203.0.113.7", hostname=hostname)
    _add(agent, alert)
    return alert, agent


def _playbook(graph, group="blue", name="pb", actions=()):
    from worker.models import SoarAction, SoarPlaybook
    from worker.soar.graph import trigger_event, validate
    pb = SoarPlaybook(id=uuid.uuid4(), name=name, group_id=group, is_enabled=True,
                      graph=validate(graph) if graph else None,
                      trigger_event=trigger_event(validate(graph)) if graph else None,
                      trigger_conditions={} if graph else {"match": "all", "conditions": []})
    _add(pb)  # no ORM relationship, so actions go in after the playbook row exists
    _add(*[SoarAction(playbook_id=pb.id, **a) for a in actions])
    return pb


def _dispatch(event, alert, group="blue", **extra):
    from worker.soar.engine import dispatch
    trigger = {"alert_id": str(alert.id), "severity": alert.severity, "rule_title": alert.title,
               "source_ip": alert.source_ip, "hostname": alert.hostname, **extra}
    return _run(dispatch(event, trigger, group_id=group))


def _execute(run_id):
    from worker.soar.engine import execute_run
    return _run(execute_run(uuid.UUID(run_id)))


def _get(model, **where):
    from sqlalchemy import select

    from worker.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as s:
            q = select(model)
            for k, v in where.items():
                q = q.where(getattr(model, k) == v)
            return (await s.execute(q)).scalars().all()
    return _run(go())


def _set_secret(name, value):
    from sqlalchemy import text

    from worker.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as s:
            await s.execute(text("INSERT INTO platform_settings VALUES (:k, :v)"), {"k": f"soar_secret_{name}", "v": value})
            await s.commit()
    _run(go())


def _steps(run_id):
    from worker.models import SoarRunStep
    return {s.node_id: s for s in _get(SoarRunStep, run_id=uuid.UUID(run_id))}


def _run_row(run_id):
    from worker.models import SoarRun
    return _get(SoarRun, id=uuid.UUID(run_id))[0]


TI_GRAPH = {
    "nodes": [
        {"id": "t", "type": "trigger", "params": {"event": "alert.triaged", "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]}]}},
        {"id": "ti", "type": "http", "params": {"url": "https://ti.example/ip/{{ trigger.source_ip }}",
                                                "headers": {"x-key": "{{ secrets.TI_KEY }}"},
                                                "extract": {"score": "body.data.score"}}},
        {"id": "check", "type": "if", "params": {"conditions": [
            {"field": "steps.ti.data.score", "operator": "gte", "value": 80}]}},
        {"id": "block", "type": "response", "params": {"operation": "block_ip", "duration_seconds": 600}},
        {"id": "low", "type": "case", "params": {"operation": "add_note", "content": "low score {{ steps.ti.data.score }}"}},
        {"id": "ti_down", "type": "case", "params": {"operation": "add_note", "content": "TI failed: {{ steps.ti.error }}"}},
    ],
    "edges": [
        {"from": "t", "output": "main", "to": "ti"},
        {"from": "ti", "output": "main", "to": "check"},
        {"from": "ti", "output": "error", "to": "ti_down"},
        {"from": "check", "output": "true", "to": "block"},
        {"from": "check", "output": "false", "to": "low"},
    ],
}


def test_dispatch_matches_event_and_conditions(db):
    alert, _ = _alert_and_agent()
    _playbook(TI_GRAPH)
    assert _dispatch("alert.created", alert) == []                     # wrong event
    assert _dispatch("alert.triaged", alert, severity="low") == []      # trigger condition fails
    assert _dispatch("alert.triaged", alert, group="red") == []         # other tenant
    [run_id] = _dispatch("alert.triaged", alert)
    assert _run_row(run_id).status == "queued"


def test_branch_true_blocks_ip_and_redacts_secrets(db, monkeypatch):
    from worker.models import AgentTask, AlertNote
    from worker.soar import nodes

    _set_secret("TI_KEY", "k-123")
    http = FakeHTTP({"data": {"score": 95}})
    monkeypatch.setattr(nodes, "_send", http)
    alert, agent = _alert_and_agent()
    _playbook(TI_GRAPH)
    [run_id] = _dispatch("alert.triaged", alert)

    assert _execute(run_id) == "success"
    assert http.calls[0]["url"] == "https://ti.example/ip/203.0.113.7"
    assert http.calls[0]["headers"] == {"x-key": "k-123"}
    steps = _steps(run_id)
    assert set(steps) == {"t", "ti", "check", "block"}
    assert steps["ti"].input["headers"] == {"x-key": "••••"}            # secret never stored
    assert steps["check"].output_name == "true"
    [task] = _get(AgentTask, agent_id=agent.id)
    assert task.task_type == "block_ip" and task.params["ip"] == "203.0.113.7"
    assert task.params["duration_seconds"] == 600
    assert any("block_ip" in n.content for n in _get(AlertNote, alert_id=alert.id))


def test_branch_false_and_error_edge(db, monkeypatch):
    from worker.models import AgentTask, AlertNote
    from worker.soar import nodes

    _set_secret("TI_KEY", "k-123")
    alert, _ = _alert_and_agent()
    _playbook(TI_GRAPH)
    monkeypatch.setattr(nodes, "_send", FakeHTTP({"data": {"score": 12}}))
    [run_id] = _dispatch("alert.triaged", alert)
    assert _execute(run_id) == "success"
    assert set(_steps(run_id)) == {"t", "ti", "check", "low"}
    assert _get(AgentTask) == []
    assert any(n.content == "low score 12" for n in _get(AlertNote, alert_id=alert.id))

    monkeypatch.setattr(nodes, "_send", FakeHTTP(503))
    [run_id] = _dispatch("alert.triaged", alert)
    assert _execute(run_id) == "success"
    steps = _steps(run_id)
    assert steps["ti"].status == "error" and steps["ti"].output_name == "error"
    assert set(steps) == {"t", "ti", "ti_down"}
    assert any(n.content == "TI failed: HTTP 503" for n in _get(AlertNote, alert_id=alert.id))


def test_error_without_edge_fails_run_and_retry_recovers(db, monkeypatch):
    from worker.soar import nodes
    from worker.soar.nodes import NodeError

    graph = {"nodes": [{"id": "t", "type": "trigger", "params": {"event": "alert.created"}},
                       {"id": "call", "type": "http", "retry": 1, "params": {"url": "https://x.example"}}],
             "edges": [{"from": "t", "output": "main", "to": "call"}]}
    alert, _ = _alert_and_agent()
    _playbook(graph)

    monkeypatch.setattr(nodes, "_send", FakeHTTP(NodeError("boom"), {"ok": 1}))
    [run_id] = _dispatch("alert.created", alert)
    assert _execute(run_id) == "success"
    assert _steps(run_id)["call"].attempts == 2

    monkeypatch.setattr(nodes, "_send", FakeHTTP(NodeError("still down")))
    [run_id] = _dispatch("alert.created", alert)
    assert _execute(run_id) == "failed"
    run = _run_row(run_id)
    assert run.status == "failed" and "still down" in run.error and run.finished_at
    assert _steps(run_id)["call"].attempts == 2


def test_missing_secret_fails_node_without_calling_out(db, monkeypatch):
    from worker.soar import nodes

    graph = {"nodes": [{"id": "t", "type": "trigger", "params": {"event": "alert.created"}},
                       {"id": "call", "type": "http", "retry": 2, "params": {
                           "url": "https://x.example", "headers": {"Authorization": "Bearer {{ secrets.NOPE }}"}}},
                       {"id": "note", "type": "case", "params": {"operation": "add_note", "content": "{{ steps.call.error }}"}}],
             "edges": [{"from": "t", "output": "main", "to": "call"}, {"from": "call", "output": "error", "to": "note"}]}
    http = FakeHTTP({"ok": 1})
    monkeypatch.setattr(nodes, "_send", http)
    alert, _ = _alert_and_agent()
    _playbook(graph)
    [run_id] = _dispatch("alert.created", alert)
    assert _execute(run_id) == "success"
    step = _steps(run_id)["call"]
    assert step.status == "error" and "soar_secret_NOPE" in step.error and step.attempts == 1
    assert http.calls == []


APPROVAL_GRAPH = {
    "nodes": [
        {"id": "t", "type": "trigger", "params": {"event": "alert.created"}},
        {"id": "ask", "type": "approval", "params": {"message": "Isolate {{ trigger.hostname }}?", "timeout_minutes": 30}},
        {"id": "iso", "type": "response", "params": {"operation": "isolate_host"}},
        {"id": "no", "type": "case", "params": {"operation": "add_note", "content": "not isolated: {{ steps.ask.reason }}"}},
    ],
    "edges": [{"from": "t", "output": "main", "to": "ask"},
              {"from": "ask", "output": "approved", "to": "iso"},
              {"from": "ask", "output": "rejected", "to": "no"}],
}


def _decide(run_id, decision):
    from worker.database import AsyncSessionLocal
    from worker.models import SoarRun

    async def go():
        async with AsyncSessionLocal() as s:
            run = await s.get(SoarRun, uuid.UUID(run_id))
            run.context = {**run.context, "decision": {"node": run.waiting_node, "decision": decision, "by_name": "ana"}}
            run.status = "resume"
            await s.commit()
    _run(go())


def test_approval_waits_then_resumes_on_approve(db):
    from worker.models import Agent, AgentTask
    from worker.soar.engine import _claim

    alert, agent = _alert_and_agent()
    _playbook(APPROVAL_GRAPH)
    [run_id] = _dispatch("alert.created", alert)
    assert [str(i) for i in _run(_claim(5))] == [run_id]
    assert _execute(run_id) == "waiting"
    run = _run_row(run_id)
    assert run.status == "waiting" and run.waiting_node == "ask"
    assert run.context["steps"]["ask"]["message"] == "Isolate web01?"
    assert _get(AgentTask) == []
    assert _run(_claim(5)) == []                       # waiting runs are not picked up

    _decide(run_id, "approved")
    assert [str(i) for i in _run(_claim(5))] == [run_id]
    assert _execute(run_id) == "success"
    steps = _steps(run_id)
    assert steps["ask"].output_name == "approved" and steps["ask"].output["by_name"] == "ana"
    [task] = _get(AgentTask, agent_id=agent.id)
    assert task.task_type == "isolate_host"
    assert _get(Agent, id=agent.id)[0].is_isolated is True
    assert "no" not in steps


def test_approval_timeout_takes_rejected_branch(db):
    from worker.database import AsyncSessionLocal
    from worker.models import AgentTask, AlertNote, SoarRun
    from worker.soar.engine import _expire_and_reap

    alert, _ = _alert_and_agent()
    _playbook(APPROVAL_GRAPH)
    [run_id] = _dispatch("alert.created", alert)
    assert _execute(run_id) == "waiting"

    async def expire():
        async with AsyncSessionLocal() as s:
            run = await s.get(SoarRun, uuid.UUID(run_id))
            run.wait_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            await s.commit()
    _run(expire())
    _run(_expire_and_reap())
    assert _run_row(run_id).status == "resume"
    assert _execute(run_id) == "success"
    assert _get(AgentTask) == []
    assert any(n.content == "not isolated: timeout" for n in _get(AlertNote, alert_id=alert.id))


def test_legacy_playbook_runs_once_on_creation(db):
    from worker.models import AlertNote

    alert, _ = _alert_and_agent()
    _playbook(None, actions=[{"action_type": "add_note", "order_index": 0, "params": {"content": "legacy ran"}}])
    assert _dispatch("alert.triaged", alert, ai_verdict="escalate") == []
    [run_id] = _dispatch("alert.created", alert)
    assert _execute(run_id) == "success"
    assert [n.content for n in _get(AlertNote, alert_id=alert.id)] == ["legacy ran"]


def test_cancelled_run_stops(db, monkeypatch):
    from worker.soar.engine import _claim

    alert, _ = _alert_and_agent()
    _playbook(APPROVAL_GRAPH)
    [run_id] = _dispatch("alert.created", alert)
    _execute(run_id)

    from worker.database import AsyncSessionLocal
    from worker.models import SoarRun

    async def cancel():
        async with AsyncSessionLocal() as s:
            run = await s.get(SoarRun, uuid.UUID(run_id))
            run.status = "cancelled"
            await s.commit()
    _run(cancel())
    assert _run(_claim(5)) == []
    assert _run_row(run_id).status == "cancelled"
