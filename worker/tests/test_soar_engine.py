import pytest
from worker.soar_engine import _matches_trigger

def _alert(severity="high", rule_title="SQL Injection", source_ip="1.2.3.4",
           hostname="web01", user_name=None, tags=None, mitre_tags=None):
    return {
        "severity": severity,
        "rule_title": rule_title,
        "source_ip": source_ip,
        "hostname": hostname,
        "user_name": user_name,
        "tags": tags if tags is not None else ["attack.initial_access", "attack.t1190"],
        "mitre_tags": mitre_tags if mitre_tags is not None else ["attack.t1190"],
    }

def test_match_all_passes():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_match_all_fails_one():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "Brute Force"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is False

def test_match_any_passes():
    trigger = {
        "match": "any",
        "conditions": [
            {"field": "severity", "operator": "eq", "value": "low"},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_eq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "eq", "value": "high"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(severity="low")) is False

def test_neq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "neq", "value": "low"}]}
    assert _matches_trigger(trigger, _alert()) is True

def test_not_null_operator():
    trigger = {"match": "all", "conditions": [{"field": "source_ip", "operator": "not_null", "value": None}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(source_ip=None)) is False

def test_tags_contains():
    trigger = {"match": "all", "conditions": [{"field": "tags", "operator": "contains", "value": "attack.t1190"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(tags=[])) is False

def test_empty_conditions_matches():
    trigger = {"match": "all", "conditions": []}
    assert _matches_trigger(trigger, _alert()) is True


# ─── Response actions (isolate / block_ip) ──────────────────────────────────
import asyncio
import uuid

from worker import soar_engine
from worker.models import AgentTask, AlertNote


class _FakeSession:
    def __init__(self, agent=None):
        self.agent = agent
        self.added = []
        self.executed = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, stmt):
        self.executed.append(stmt)
        agent = self.agent

        class _Result:
            def scalar_one_or_none(self_inner):
                return agent
        return _Result()

    async def commit(self):
        pass


class _Agent:
    def __init__(self):
        self.id = uuid.uuid4()


def _run_action(monkeypatch, handler, ctx, params=None, agent=None):
    session = _FakeSession(agent)
    monkeypatch.setattr(soar_engine, "AsyncSessionLocal", lambda: session)
    asyncio.run(handler(uuid.uuid4(), ctx, params or {}))
    return session


def _tasks(session):
    return [o for o in session.added if isinstance(o, AgentTask)]


def test_block_ip_queues_task_with_params(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_block_ip,
                    {"source_ip": "203.0.113.7", "hostname": "web01", "group_id": "g1"},
                    {"duration_seconds": 600}, agent=_Agent())
    [task] = _tasks(s)
    assert task.task_type == "block_ip"
    assert task.params["ip"] == "203.0.113.7"
    assert task.params["duration_seconds"] == 600


def test_block_ip_rejects_non_ip_source(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_block_ip,
                    {"source_ip": "1.2.3.4'; rm -rf / #", "hostname": "web01"},
                    agent=_Agent())
    assert _tasks(s) == []
    assert any(isinstance(o, AlertNote) for o in s.added)


def test_block_ip_bad_duration_falls_back(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_block_ip,
                    {"source_ip": "2001:db8::1", "hostname": "web01"},
                    {"duration_seconds": "abc"}, agent=_Agent())
    [task] = _tasks(s)
    assert task.params["duration_seconds"] == 3600


def test_block_ip_no_agent_leaves_note(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_block_ip,
                    {"source_ip": "203.0.113.7", "hostname": "web01"}, agent=None)
    assert _tasks(s) == []
    assert any(isinstance(o, AlertNote) for o in s.added)


def test_isolate_queues_task_and_marks_agent(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_isolate_agent,
                    {"hostname": "web01", "group_id": "g1"}, agent=_Agent())
    [task] = _tasks(s)
    assert task.task_type == "isolate_host"
    assert task.params == {}
    assert any("is_isolated" in str(stmt) for stmt in s.executed)


def test_agent_lookup_is_group_scoped(monkeypatch):
    s = _run_action(monkeypatch, soar_engine._action_isolate_agent,
                    {"hostname": "web01", "group_id": "tenant-a"}, agent=_Agent())
    lookup = str(s.executed[0].compile(compile_kwargs={"literal_binds": True}))
    assert "agents.group_id = 'tenant-a'" in lookup
