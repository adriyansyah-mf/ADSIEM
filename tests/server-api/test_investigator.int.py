# tests/server-api/test_investigator.int.py
"""AI case investigation end to end against a real Postgres, with a scripted
model standing in for the LLM and a fake agent answering flows.

Needs TEST_DATABASE_URL and DATABASE_URL pointing at the same database
(app.core.database binds its engine from DATABASE_URL at import).
"""
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


class Scripted:
    """bind_tools/ainvoke like NineRouterChatModel; each turn is computed from the conversation."""

    def __init__(self, script):
        self.script = script
        self.seen = []

    def bind_tools(self, tools):
        self.tool_names = {t.name for t in tools}
        return self

    async def ainvoke(self, messages):
        from langchain_core.messages import AIMessage, ToolMessage
        self.seen.append(list(messages))  # a copy: the caller appends the reply to its list
        results = [json.loads(m.content) for m in messages if isinstance(m, ToolMessage)]
        step = self.script(len(self.seen), results)
        if isinstance(step, str):
            return AIMessage(content=step)
        name, args = step
        return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{len(self.seen)}"}])


TMP_ARTIFACT = """name: AI.Linux.TmpProcs
description: processes running from /tmp
sources:
  - name: Procs
    plugin: pslist
    detection:
      selection:
        Exe|startswith: /tmp/
      condition: selection
"""
READ_ARTIFACT = """name: AI.Linux.ReadAny
description: read a file
parameters:
  - name: Path
    default: /etc/hostname
sources:
  - name: File
    plugin: read_file
    args:
      path: "{{Path}}"
"""


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield
    _run(engine.dispose())


def _seed():
    from app.core.database import AsyncSessionLocal
    from app.models.models import Agent, Alert, Case, PlatformSetting, Role, User

    async def go():
        async with AsyncSessionLocal() as db:
            role = Role(name=f"analyst-{uuid.uuid4().hex[:6]}")
            db.add(role)
            await db.flush()
            user = User(username=f"ana-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex}@x", password_hash="x",
                        role_id=role.id, group_id="blue")
            agent = Agent(name="web01", hostname="web01", group_id="blue", token_hash=uuid.uuid4().hex,
                          status="online", last_seen_at=datetime.now(timezone.utc),
                          flow_poll_at=datetime.now(timezone.utc))
            db.add_all([user, agent])
            await db.flush()
            alert = Alert(title="Reverse shell from /tmp", severity="high", group_id="blue",
                          hostname="web01", agent_id=agent.id, source_ip="203.0.113.9")
            db.add(alert)
            await db.flush()
            case = Case(title="web01 compromise?", severity="high", group_id="blue", alert_id=alert.id)
            db.add(case)
            if not await db.get(PlatformSetting, "ninerouter_api_key"):
                db.add(PlatformSetting(key="ninerouter_api_key", value="test-key", is_secret=True))
            await db.commit()
            return user.id, agent.id, case.id
    return _run(go())


async def _fake_agent(stop: asyncio.Event):
    """Answer every scheduled flow like an agent: rows for pslist, finished."""
    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.models.models import Flow, FlowRowBatch

    while not stop.is_set():
        async with AsyncSessionLocal() as db:
            for flow in (await db.execute(select(Flow).where(Flow.status == "scheduled"))).scalars().all():
                for src in flow.request["sources"]:
                    if src["plugin"] == "pslist":
                        db.add(FlowRowBatch(flow_id=flow.id, source=src["name"], rows=[
                            {"Pid": 4242, "Name": "kworkerd", "Exe": "/tmp/.x/kworkerd", "CommandLine": "kworkerd -c 203.0.113.9:443"},
                        ]))
                await db.execute(update(Flow).where(Flow.id == flow.id).values(status="finished", total_rows=1))
            await db.commit()
        await asyncio.sleep(0.5)


def _investigate(script, monkeypatch, user_id, case_id, cancel_after=None):
    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation
    from app.services import investigator

    model = Scripted(script)
    monkeypatch.setattr(investigator, "make_chat_model", lambda *a, **k: model)

    async def go():
        async with AsyncSessionLocal() as db:
            inv = CaseInvestigation(case_id=case_id, group_id="blue", started_by=user_id, steps=[])
            db.add(inv)
            await db.commit()
            inv_id = inv.id
        stop = asyncio.Event()
        agent = asyncio.create_task(_fake_agent(stop))
        run = asyncio.create_task(investigator.run_investigation(inv_id))
        if cancel_after:
            await asyncio.sleep(cancel_after)
            await investigator._set(inv_id, cancel_requested=True)
        await asyncio.wait_for(run, 60)
        stop.set()
        await agent
        async with AsyncSessionLocal() as db:
            return await db.get(CaseInvestigation, inv_id)
    return _run(go()), model


def test_investigation_collects_creates_artifacts_and_reports(env, monkeypatch):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseNote, Flow, FlowArtifact, FlowLog

    user_id, agent_id, case_id = _seed()
    state = {}

    def script(turn, results):
        if turn == 1:
            return ("list_artifacts", {"os": "linux"})
        if turn == 2:
            assert any(a["name"] == "Linux.Sys.Pslist" for a in results[-1]["artifacts"])
            return ("create_artifact", {"yaml_text": TMP_ARTIFACT, "reason": "find processes from /tmp"})
        if turn == 3:
            assert results[-1]["created"] == "AI.Linux.TmpProcs"
            return ("run_artifact", {"artifact": "AI.Linux.TmpProcs", "host": "web01", "reason": "check /tmp"})
        if turn == 4:
            state["flow"] = results[-1]["flow_id"]
            assert results[-1]["status"] == "finished"
            assert results[-1]["sources"][0]["rows"][0]["Exe"] == "/tmp/.x/kworkerd"
            return ("create_artifact", {"yaml_text": READ_ARTIFACT})
        if turn == 5:
            return ("run_artifact", {"artifact": "AI.Linux.ReadAny", "host": "web01", "params": {"Path": "/etc/shadow"}})
        if turn == 6:
            assert "refused" in results[-1]["error"]
            return ("get_flow_rows", {"flow_id": state["flow"], "contains": "203.0.113.9"})
        if turn == 7:
            assert results[-1]["matching_rows"] == 1
            return ("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": "db99"})
        if turn == 8:
            assert "no agent" in results[-1]["error"]
            return ("create_artifact", {"yaml_text": TMP_ARTIFACT.replace("AI.Linux.TmpProcs", "Linux.Mine")})
        if turn == 9:
            assert "must start with 'AI.'" in results[-1]["error"]
            return ("## Summary\nA miner-like process ran from /tmp and called back to 203.0.113.9.\n\n"
                    "VERDICT: true_positive")
        raise AssertionError(f"unexpected turn {turn}")

    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished", inv.error
    assert inv.verdict == "true_positive" and "203.0.113.9" in inv.report
    kinds = [s["kind"] for s in inv.steps]
    assert {"started", "context", "tool", "artifact", "flow", "flow_result", "refused", "finished"} <= set(kinds)
    # the model saw the case before its first move
    assert "Reverse shell from /tmp" in model.seen[0][1].content

    async def check():
        async with AsyncSessionLocal() as db:
            notes = (await db.execute(select(CaseNote).where(CaseNote.case_id == case_id))).scalars().all()
            assert len(notes) == 1 and notes[0].is_ai_generated and "true positive" in notes[0].content
            flows = (await db.execute(select(Flow).where(Flow.agent_id == agent_id))).scalars().all()
            assert [f.artifact for f in flows] == ["AI.Linux.TmpProcs"]  # the shadow read never got scheduled
            assert flows[0].created_by == user_id
            log = (await db.execute(select(FlowLog.message).where(FlowLog.flow_id == flows[0].id))).scalars().first()
            assert "AI investigation" in log
            art = (await db.execute(select(FlowArtifact).where(FlowArtifact.name == "AI.Linux.TmpProcs"))).scalar_one()
            assert art.group_id == "blue" and art.description.startswith("[AI investigation]")
    _run(check())


def test_round_budget_forces_a_report(env, monkeypatch):
    from app.services import investigator

    user_id, _, case_id = _seed()
    monkeypatch.setattr(investigator, "MAX_ROUNDS", 3)

    def script(turn, results):
        return "## Summary\nOut of budget.\nVERDICT: inconclusive" if turn == 3 else ("list_hosts", {})

    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished" and inv.verdict == "inconclusive"
    assert "Budget exhausted" in model.seen[-1][-1].content


def test_cancel_stops_the_run(env, monkeypatch):
    user_id, _, case_id = _seed()

    def script(turn, results):
        return ("list_hosts", {})  # would run forever

    import app.services.investigator as investigator

    async def slow_hosts(ctx, hostname_contains=""):
        await asyncio.sleep(0.3)
        return {"hosts": []}
    monkeypatch.setattr(investigator, "list_hosts", slow_hosts)
    inv, _ = _investigate(script, monkeypatch, user_id, case_id, cancel_after=1.0)
    assert inv.status == "cancelled"
    assert inv.steps[-1]["kind"] == "cancelled"
