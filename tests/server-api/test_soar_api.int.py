# tests/server-api/test_soar_api.int.py
"""SOAR workflow API: graphs are validated on save, legacy playbooks convert,
manual runs are queued from an alert, approvals only apply to waiting runs,
other groups get 404, and every write needs agents:manage.
Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import inspect
import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()
USER = SimpleNamespace(id=uuid.uuid4(), group_id="blue", username="ana")

GRAPH = {
    "nodes": [
        {"id": "t", "type": "trigger", "params": {"event": "alert.triaged", "match": "all",
                                                   "conditions": [{"field": "severity", "operator": "eq", "value": "critical"}]}},
        {"id": "ask", "type": "approval", "params": {"message": "Block {{ trigger.source_ip }}?"}},
        {"id": "block", "type": "response", "params": {"operation": "block_ip"}},
    ],
    "edges": [{"from": "t", "output": "main", "to": "ask"}, {"from": "ask", "output": "approved", "to": "block"}],
}


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield
    _run(engine.dispose())


def _call(fn, *args, **kwargs):
    from app.core.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as db:
            return await fn(*args, db=db, **kwargs)
    return _run(go())


def _status(fn, *args, **kwargs):
    with pytest.raises(HTTPException) as exc:
        _call(fn, *args, **kwargs)
    return exc.value


def test_create_validates_graph_and_reports_every_error(env):
    from app.api.routes import soar as s
    pb = _call(s.create_playbook, s.PlaybookIn(name="block on approval", graph=GRAPH),
               current_user=USER, group_id="blue")
    assert pb["legacy"] is False and pb["trigger_event"] == "alert.triaged"
    assert [n["id"] for n in pb["graph"]["nodes"]] == ["t", "ask", "block"]

    bad = {"nodes": GRAPH["nodes"] + [{"id": "x", "type": "code"}], "edges": GRAPH["edges"] + [
        {"from": "block", "output": "main", "to": "t"}]}
    err = _status(s.create_playbook, s.PlaybookIn(name="bad", graph=bad), current_user=USER, group_id="blue")
    assert err.status_code == 422
    assert any("unknown type" in e for e in err.detail["errors"])
    assert any("Trigger" in e for e in err.detail["errors"])


def test_legacy_playbook_converts_when_graph_saved(env):
    from app.api.routes import soar as s
    pb = _call(s.create_playbook, s.PlaybookIn(name="old", trigger_conditions={"conditions": [
        {"field": "severity", "operator": "eq", "value": "high"}]}), current_user=USER, group_id="blue")
    pid = uuid.UUID(pb["id"])
    _call(s.add_action, pid, s.ActionIn(action_type="add_note", params={"content": "hi"}),
          current_user=USER, group_filter="blue")
    got = _call(s.get_playbook, pid, current_user=USER, group_filter="blue")
    assert got["legacy"] is True and [n["type"] for n in got["graph"]["nodes"]] == ["trigger", "case"]

    saved = _call(s.save_graph, pid, s.GraphIn(graph=got["graph"]), current_user=USER, group_filter="blue")
    assert saved["legacy"] is False and saved["actions"] == []
    assert saved["trigger_conditions"]["conditions"][0]["field"] == "severity"
    err = _status(s.add_action, pid, s.ActionIn(action_type="add_note"), current_user=USER, group_filter="blue")
    assert err.status_code == 409


def test_parse_curl_and_validate(env):
    from app.api.routes import soar as s
    out = _run(s.parse_curl_command(s.CurlIn(command="curl -X PUT https://fw.example/api -H 'X-K: 1' --json '{\"a\":1}'"),
                                    current_user=USER))
    assert out["params"]["method"] == "PUT" and out["params"]["body"] == {"a": 1}
    with pytest.raises(HTTPException) as exc:
        _run(s.parse_curl_command(s.CurlIn(command="rm -rf /"), current_user=USER))
    assert exc.value.status_code == 422
    assert _run(s.validate_graph(s.GraphIn(graph=GRAPH), current_user=USER))["ok"] is True
    res = _run(s.validate_graph(s.GraphIn(graph={"nodes": [], "edges": []}), current_user=USER))
    assert res["ok"] is False and res["errors"]


def _alert(group="blue"):
    from app.core.database import AsyncSessionLocal
    from app.models.models import Alert

    async def go():
        async with AsyncSessionLocal() as db:
            a = Alert(title="Login after brute force", severity="critical", group_id=group,
                      source_ip="203.0.113.9", hostname="web01")
            db.add(a)
            await db.commit()
            return a.id
    return _run(go())


def test_manual_run_decision_and_cancel(env):
    from app.api.routes import soar as s
    from app.core.database import AsyncSessionLocal
    from app.models.models import SoarRun

    pb = _call(s.create_playbook, s.PlaybookIn(name="manual", graph=GRAPH), current_user=USER, group_id="blue")
    pid = uuid.UUID(pb["id"])
    alert_id = _alert()
    run = _call(s.run_playbook, pid, s.RunIn(alert_id=alert_id), current_user=USER, group_filter="blue")
    assert run["status"] == "queued" and run["trigger_event"] == "manual"
    rid = uuid.UUID(run["id"])

    async def ctx():
        async with AsyncSessionLocal() as db:
            return (await db.get(SoarRun, rid)).context
    c = _run(ctx())
    assert c["trigger"]["source_ip"] == "203.0.113.9" and c["queue"] == ["t"]

    # not waiting yet → no decision
    assert _status(s.decide, rid, s.DecisionIn(decision="approved"), current_user=USER,
                   group_filter="blue").status_code == 409

    async def park():
        async with AsyncSessionLocal() as db:
            r = await db.get(SoarRun, rid)
            r.status, r.waiting_node = "waiting", "ask"
            r.context = {**r.context, "steps": {"ask": {"message": "Block?"}}}
            await db.commit()
    _run(park())
    assert _call(s.list_runs, status="waiting", limit=50, current_user=USER, group_filter="blue")[0]["approval"] == {"message": "Block?"}
    assert _status(s.decide, rid, s.DecisionIn(decision="approved"), current_user=USER,
                   group_filter="red").status_code == 404
    assert _call(s.decide, rid, s.DecisionIn(decision="approved", comment="go"), current_user=USER,
                 group_filter="blue")["status"] == "resume"
    c = _run(ctx())
    assert c["decision"]["decision"] == "approved" and c["decision"]["by_name"] == "ana" and c["decision"]["node"] == "ask"

    detail = _call(s.get_run, rid, current_user=USER, group_filter="blue")
    assert detail["graph"]["nodes"][0]["id"] == "t" and detail["steps"] == []
    assert _status(s.get_run, rid, current_user=USER, group_filter="red").status_code == 404
    assert _call(s.cancel_run, rid, current_user=USER, group_filter="blue") == {"ok": True}
    assert _status(s.cancel_run, rid, current_user=USER, group_filter="blue").status_code == 409


def test_other_group_cannot_see_or_run(env):
    from app.api.routes import soar as s
    pb = _call(s.create_playbook, s.PlaybookIn(name="blue only", graph=GRAPH), current_user=USER, group_id="blue")
    pid = uuid.UUID(pb["id"])
    for fn, extra in ((s.get_playbook, {}), (s.delete_playbook, {})):
        assert _status(fn, pid, current_user=USER, group_filter="red", **extra).status_code == 404
    assert _status(s.run_playbook, pid, s.RunIn(), current_user=USER, group_filter="red").status_code == 404
    red_alert = _alert(group="red")
    assert _status(s.run_playbook, pid, s.RunIn(alert_id=red_alert), current_user=USER,
                   group_filter="blue").status_code == 404


def test_every_write_needs_agents_manage():
    from app.api.routes import soar as s
    for route in s.router.routes:
        writes = route.methods & {"POST", "PUT", "PATCH", "DELETE"}
        if not writes or route.path in ("/api/soar/validate", "/api/soar/parse-curl"):
            continue
        defaults = [p.default for p in inspect.signature(route.endpoint).parameters.values()]
        assert any(getattr(d, "dependency", None) is s.Manage for d in defaults), route.path
