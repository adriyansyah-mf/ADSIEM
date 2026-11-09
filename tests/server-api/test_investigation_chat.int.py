# tests/server-api/test_investigation_chat.int.py
"""Follow-up chat on a finished AI investigation: one bounded tool-calling turn
per analyst message, read tools run at once, changes become proposals.

A disposable schema of TEST_DATABASE_URL; a scripted model stands in for the LLM
(pattern: test_investigator.int.py)."""
import json
import os
from datetime import datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest


class Scripted:
    """bind_tools/ainvoke like NineRouterChatModel. script(turn, results, messages) returns
    text, one (name, args) call, or a list of calls."""

    def __init__(self, script):
        self.script = script
        self.seen = []
        self.bound = []  # per call: whether it went through bind_tools (tools offered)
        self.tool_names: set[str] = set()

    def bind_tools(self, tools):
        self.tool_names = {t.name for t in tools}
        model = self

        class Bound:
            async def ainvoke(self, messages):
                return await model._invoke(messages, True)
        return Bound()

    async def ainvoke(self, messages):
        return await self._invoke(messages, False)

    async def _invoke(self, messages, bound):
        from langchain_core.messages import AIMessage, ToolMessage
        self.seen.append(list(messages))
        self.bound.append(bound)
        results = [json.loads(m.content) for m in messages if isinstance(m, ToolMessage)]
        step = self.script(len(self.seen), results, messages)
        if isinstance(step, str):
            return AIMessage(content=step)
        calls = step if isinstance(step, list) else [step]
        return AIMessage(content="", tool_calls=[
            {"name": n, "args": a, "id": f"c{len(self.seen)}_{i}"} for i, (n, a) in enumerate(calls)])


def _user(uid, perms=("cases:manage", "alerts:read"), group="blue", role="analyst"):
    return SimpleNamespace(id=uid, username="ana", group_id=group,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture
async def chat(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs TEST_DATABASE_URL (disposable PostgreSQL)")
    import httpx
    from fastapi import FastAPI
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.routes import investigation_chat
    from app.core.database import Base, get_db
    from app.core.deps import get_current_user
    from app.models import models
    from app.services import investigator

    namespace = "inv_chat_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as db:
        await db.execute(text("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"))
        await db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{namespace},public"}},
                                 execution_options={"schema_translate_map": {None: namespace}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.run_sync(Base.metadata.create_all)
        async with sessions() as db:
            role = models.Role(name="analyst")
            db.add(role)
            await db.flush()
            users, agents, cases, invs = {}, {}, {}, {}
            for group in ("blue", "red"):
                u = models.User(username=f"ana-{group}", email=f"{group}@x", password_hash="x", role_id=role.id,
                                group_id=group)
                a = models.Agent(name=f"{group}-host", hostname=f"{group}-host", group_id=group,
                                 token_hash=uuid4().hex, status="online")
                db.add_all([u, a])
                await db.flush()
                alert = models.Alert(title="Reverse shell", severity="high", group_id=group, hostname=a.hostname,
                                     agent_id=a.id, source_ip="203.0.113.9")
                db.add(alert)
                await db.flush()
                c = models.Case(title=f"{group} compromise", severity="high", group_id=group, alert_id=alert.id,
                                ioc_data={"ioc_keys": ["ip:203.0.113.9"]})
                db.add(c)
                await db.flush()
                users[group], agents[group], cases[group] = u.id, a.id, c.id
                for status in ("finished", "running", "queued"):
                    inv = models.CaseInvestigation(case_id=c.id, group_id=group, status=status,
                                                   verdict="true_positive" if status == "finished" else None,
                                                   report="Reverse shell confirmed." if status == "finished" else None)
                    db.add(inv)
                    await db.flush()
                    invs[(group, status)] = inv.id
            ev = models.InvestigationEvidence(investigation_id=invs[("blue", "finished")], group_id="blue",
                                              evidence_type="event", source_type="event", title="nc -e /bin/sh",
                                              summary="netcat reverse shell to 203.0.113.9", content_hash="h1",
                                              pinned=True)
            db.add(ev)
            db.add(models.PlatformSetting(key="ninerouter_api_key", value="test-key", is_secret=True))
            await db.commit()
            ev_id = ev.id

        env = SimpleNamespace(sessions=sessions, users=users, agents=agents, cases=cases, invs=invs, evidence=ev_id,
                              user=_user(users["blue"]), model=None)

        async def database():
            async with sessions() as db:
                yield db

        def model(api_key, model, effort):
            env.model_args = (api_key, model, effort)
            return env.model

        monkeypatch.setattr(investigator, "make_chat_model", model)
        app = FastAPI()
        app.include_router(investigation_chat.router)
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_current_user] = lambda: env.user
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()


def _url(env, group="blue", status="finished"):
    return f"/api/investigations/{env.invs[(group, status)]}/chat"


async def test_turn_reads_evidence_proposes_isolation_and_keeps_history(chat):
    agent = str(chat.agents["blue"])

    def script(turn, results, messages):
        if turn == 1:
            return "list_evidence", {}
        if turn == 2:
            assert results[-1]["evidence"][0]["title"] == "nc -e /bin/sh"
            return "isolate_host", {"agent_id": agent, "reason": "reverse shell to 203.0.113.9"}
        if turn == 3:
            assert results[-1]["status"] == "proposed, awaiting analyst approval"
            return "I proposed isolating blue-host; approve it to cut the reverse shell."
        return "Isolation is still waiting for your approval."

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "isolate the host"})
    assert r.status_code == 200, r.text
    body = r.json()
    user_msg, reply = body["messages"]
    assert (user_msg["role"], user_msg["content"]) == ("user", "isolate the host")
    assert user_msg["author_id"] == str(chat.users["blue"])
    assert reply["role"] == "assistant"
    assert reply["content"].startswith("I proposed isolating blue-host")
    assert [c["name"] for c in reply["tool_calls"]] == ["list_evidence", "isolate_host"]
    datetime.fromisoformat(reply["created_at"])

    [action] = body["actions"]
    assert action["tool"] == "isolate_host"
    assert action["status"] == "proposed"
    assert action["target"] == agent
    assert action["reason"] == "reverse shell to 203.0.113.9"
    assert action["message_id"] == reply["id"]
    assert action["requested_by"] == str(chat.users["blue"])
    datetime.fromisoformat(action["created_at"])

    # the model got the case, report and pinned evidence as context, and only the allowed tools
    context = chat.model.seen[0][1].content
    assert "blue compromise" in context and "Reverse shell confirmed." in context and "nc -e /bin/sh" in context
    assert "ip:203.0.113.9" in context and agent in context
    assert {"list_evidence", "get_evidence", "list_hypotheses", "case_iocs", "search_events",
            "isolate_host", "block_domain", "add_threat_ioc", "run_live_response"} <= chat.model.tool_names
    assert "run_command" not in chat.model.tool_names and "ti_lookup" not in chat.model.tool_names

    # the next turn sees the conversation so far; GET returns everything
    r = await chat.client.post(_url(chat), json={"message": "status?"})
    assert r.status_code == 200, r.text
    assert r.json()["actions"] == []
    assert any("isolate the host" in str(m.content) for m in chat.model.seen[-1])
    assert any("I proposed isolating" in str(m.content) for m in chat.model.seen[-1])

    r = await chat.client.get(_url(chat))
    assert r.status_code == 200
    got = r.json()
    assert [m["role"] for m in got["messages"]] == ["user", "assistant", "user", "assistant"]
    assert [a["id"] for a in got["actions"]] == [action["id"]]


async def test_turn_limits_tool_calls_and_proposals(chat):
    agent = str(chat.agents["blue"])
    iso = ("isolate_host", {"agent_id": agent, "reason": "r"})

    def script(turn, results, messages):
        if turn == 1:
            return [iso] * 6 + [("list_evidence", {})] * 3
        return "done"

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "go"})
    assert r.status_code == 200, r.text
    assert len(r.json()["actions"]) == 5
    from langchain_core.messages import ToolMessage
    results = [json.loads(m.content) for m in chat.model.seen[1] if isinstance(m, ToolMessage)]
    assert len(results) == 9
    assert all(x["status"] == "proposed, awaiting analyst approval" for x in results[:5])
    assert "proposal limit" in results[5]["error"]
    assert "evidence" in results[6] and "evidence" in results[7]
    assert "tool-call limit" in results[8]["error"]


async def test_turn_stops_calling_tools_once_the_budget_is_spent(chat):
    def script(turn, results, messages):
        # a model that never stops calling tools while it is offered any
        return ("list_evidence", {}) if chat.model.bound[-1] else "summary"

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "loop"})
    assert r.status_code == 200, r.text
    reply = r.json()["messages"][1]
    assert reply["content"] == "summary"
    assert len(reply["tool_calls"]) == 8
    assert chat.model.bound == [True] * 8 + [False]


async def test_bad_proposal_args_are_refused_without_a_row(chat):
    def script(turn, results, messages):
        if turn == 1:
            return [("isolate_host", {"agent_id": 7}),
                    ("block_ip", {"agent_ids": [], "ip": "1.2.3.4", "duration_seconds": 3600, "reason": "c2"}),
                    ("add_case_ioc", {"type": "nope", "value": "x", "reason": "r"}),
                    ("kill_process", {"agent_id": "a", "pid": "12", "reason": "r"})]
        return "could not propose"

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "do things"})
    assert r.status_code == 200, r.text
    assert r.json()["actions"] == []
    from langchain_core.messages import ToolMessage
    results = [json.loads(m.content) for m in chat.model.seen[1] if isinstance(m, ToolMessage)]
    assert all("error" in x for x in results), results


async def test_text_tool_calls_are_recovered(chat):
    agent = str(chat.agents["blue"])

    def script(turn, results, messages):
        if turn == 1:
            return ('<tool_call>{"name": "unisolate_host", "arguments": {"agent_id": "%s", "reason": "clean"}}'
                    '</tool_call>' % agent)
        return "proposed"

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "lift isolation"})
    assert r.status_code == 200, r.text
    assert [a["tool"] for a in r.json()["actions"]] == ["unisolate_host"]


@pytest.mark.parametrize("status", ["running", "queued"])
async def test_active_investigation_refuses_chat(chat, status):
    chat.model = Scripted(lambda *a: "never")
    r = await chat.client.post(_url(chat, status=status), json={"message": "hi"})
    assert r.status_code == 409
    assert chat.model.seen == []


async def test_other_groups_investigation_is_not_found(chat):
    chat.model = Scripted(lambda *a: "never")
    assert (await chat.client.post(_url(chat, group="red"), json={"message": "hi"})).status_code == 404
    assert (await chat.client.get(_url(chat, group="red"))).status_code == 404
    assert (await chat.client.get(f"/api/investigations/{uuid4()}/chat")).status_code == 404


async def test_no_ai_provider_is_422_and_saves_nothing(chat):
    from sqlalchemy import delete, func, select
    from app.models.models import InvestigationMessage, PlatformSetting
    async with chat.sessions() as db:
        await db.execute(delete(PlatformSetting).where(PlatformSetting.key == "ninerouter_api_key"))
        await db.commit()
    chat.model = Scripted(lambda *a: "never")
    r = await chat.client.post(_url(chat), json={"message": "hi"})
    assert r.status_code == 422
    async with chat.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(InvestigationMessage)) == 0


async def test_permissions(chat):
    chat.model = Scripted(lambda *a: "never")
    chat.user = _user(chat.users["blue"], perms=("alerts:read",))
    assert (await chat.client.post(_url(chat), json={"message": "hi"})).status_code == 403
    assert (await chat.client.get(_url(chat))).status_code == 200
    chat.user = _user(chat.users["blue"], perms=())
    assert (await chat.client.get(_url(chat))).status_code == 403


async def test_investigation_model_setting_is_used(chat):
    from app.models.models import PlatformSetting
    async with chat.sessions() as db:
        db.add(PlatformSetting(key="investigation_model", value="big-model"))
        await db.commit()
    chat.model = Scripted(lambda *a: "ok")
    r = await chat.client.post(_url(chat), json={"message": "hi"})
    assert r.status_code == 200, r.text
    assert chat.model_args[:2] == ("test-key", "big-model")
    assert UUID(r.json()["messages"][1]["id"])


async def test_time_limit_keeps_proposals_and_says_so(chat, monkeypatch):
    import asyncio
    from app.services import investigation_chat
    monkeypatch.setattr(investigation_chat, "TURN_SECONDS", 1)
    agent = str(chat.agents["blue"])

    class Slow(Scripted):
        async def _invoke(self, messages, bound):
            if self.seen:  # the second model call hangs past the turn's deadline
                await asyncio.sleep(5)
            return await super()._invoke(messages, bound)

    chat.model = Slow(lambda turn, results, messages: ("isolate_host", {"agent_id": agent, "reason": "c2"}))
    r = await chat.client.post(_url(chat), json={"message": "isolate"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "ran out of time" in body["messages"][1]["content"]
    [action] = body["actions"]
    assert action["message_id"] == body["messages"][1]["id"]


async def test_model_failure_is_a_system_message(chat):
    def script(turn, results, messages):
        raise RuntimeError("provider down")

    chat.model = Scripted(script)
    r = await chat.client.post(_url(chat), json={"message": "hi"})
    assert r.status_code == 200, r.text
    user_msg, note = r.json()["messages"]
    assert user_msg["content"] == "hi"
    assert note["role"] == "system" and "provider down" in note["content"]
