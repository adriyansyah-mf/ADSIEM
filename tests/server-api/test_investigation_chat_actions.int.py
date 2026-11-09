# tests/server-api/test_investigation_chat_actions.int.py
"""Deciding what the investigation chat proposed: an analyst allowed to do the
action approves (it runs at once, through the same paths the dashboard uses) or
rejects it; nothing ever runs twice.

A disposable schema of TEST_DATABASE_URL; Elasticsearch and the audit log are
faked (monkeypatch), Redis is the conftest fake."""
import hashlib
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest


class _Redis:
    def __init__(self):
        self.kv = {}

    async def set(self, key, value, ex=None, nx=False):
        self.kv[key] = value
        return True

CASE = ("cases:manage", "alerts:read")
ENDPOINT = ("agents:manage", "alerts:read")
BOTH = ("cases:manage", "agents:manage", "alerts:read")


def _user(uid, perms=BOTH, group="blue", role="analyst", name="boss"):
    return SimpleNamespace(id=uid, username=name, group_id=group,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture
async def act(monkeypatch):
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
    from app.core.redis_client import get_redis
    from app.models import models
    from app.services import investigation_chat_actions as actions
    from app.services import web_blocks

    namespace = "inv_chat_act_" + uuid4().hex
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
            role = models.Role(name="analyst", permissions=[models.Permission(name=n) for n in BOTH])
            db.add(role)
            await db.flush()
            users = {}
            for name, group in (("requester", "blue"), ("approver", "blue"), ("red", "red")):
                u = models.User(username=name, email=f"{name}@x", password_hash="x", role_id=role.id, group_id=group)
                db.add(u)
                await db.flush()
                users[name] = u.id
            agents = {}
            for name, group, status, polled in (("blue-host", "blue", "online", True), ("blue-off", "blue", "offline", True),
                                                ("blue-old", "blue", "online", False), ("red-host", "red", "online", True)):
                a = models.Agent(name=name, hostname=name, group_id=group, token_hash=uuid4().hex, status=status,
                                 approved=True, flow_poll_at=datetime.now(timezone.utc) if polled else None)
                db.add(a)
                await db.flush()
                agents[name] = a.id
            alert = models.Alert(title="Reverse shell", severity="high", group_id="blue", hostname="blue-host",
                                 agent_id=agents["blue-host"], source_ip="203.0.113.9")
            db.add(alert)
            await db.flush()
            case = models.Case(title="blue compromise", severity="critical", group_id="blue", alert_id=alert.id,
                               ioc_data={"ioc_keys": ["ip:203.0.113.9"], "affected_hosts": ["blue-host"]})
            db.add(case)
            await db.flush()
            inv = models.CaseInvestigation(case_id=case.id, group_id="blue", status="finished")
            db.add(inv)
            await db.flush()
            ev = models.InvestigationEvidence(investigation_id=inv.id, group_id="blue", evidence_type="event",
                                              source_type="event", title="nc -e /bin/sh", content_hash="h1")
            other_inv = models.CaseInvestigation(case_id=case.id, group_id="blue", status="finished")
            db.add_all([ev, other_inv])
            await db.flush()
            other_ev = models.InvestigationEvidence(investigation_id=other_inv.id, group_id="blue",
                                                    evidence_type="event", source_type="event", title="other",
                                                    content_hash="h2")
            db.add(other_ev)
            await db.commit()

        env = SimpleNamespace(sessions=sessions, users=users, agents=agents, case=case.id, inv=inv.id,
                              evidence=ev.id, other_evidence=other_ev.id, audits=[], es_index=[], es_delete=[],
                              es_fail=None, redis=_Redis(), models=models, actions=actions, real_user=None)
        env.user = _user(users["approver"])

        async def database():
            async with sessions() as db:
                yield db

        async def redis():
            return env.redis

        async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None):
            env.audits.append((actor_id, action, resource_id, detail))

        async def index_ioc(doc_id, doc):
            if env.es_fail:
                raise RuntimeError(env.es_fail)
            env.es_index.append((doc_id, doc))

        async def delete_ioc(doc_id):
            if env.es_fail:
                raise RuntimeError(env.es_fail)
            env.es_delete.append(doc_id)
            return True

        monkeypatch.setattr(actions, "audit_log", audit)
        monkeypatch.setattr(actions.es_client, "index_ioc", index_ioc)
        monkeypatch.setattr(actions.es_client, "delete_ioc", delete_ioc)
        async with sessions() as db:
            await web_blocks.seed_builtin_allowlist(db)
        web_blocks.invalidate()
        app = FastAPI()
        app.include_router(investigation_chat.router)
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_redis] = redis
        from fastapi import Depends
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        async def current_user(db=Depends(get_db)):
            if env.real_user is None:
                return env.user
            # like get_current_user: a real User on the request's own session
            return (await db.execute(select(models.User).options(
                selectinload(models.User.role).selectinload(models.Role.permissions))
                .where(models.User.id == env.real_user))).scalar_one()

        app.dependency_overrides[get_current_user] = current_user
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()


async def propose(env, tool, args, *, created_at=None, group="blue"):
    """A proposal row as the chat turn would store it (shape-checked by validate_proposal)."""
    actions = env.actions
    ctx = actions.ChatCtx(env.inv, env.case, group, env.users["requester"])
    target, params = actions.validate_proposal(tool, args, ctx)
    async with env.sessions() as db:
        row = env.models.InvestigationChatAction(
            investigation_id=env.inv, group_id=group, tool=tool, target=target, params=params,
            reason=args.get("reason"), requested_by=env.users["requester"],
            **({"created_at": created_at} if created_at else {}))
        db.add(row)
        await db.commit()
        return row.id


async def decide(env, action_id, approve=True, note=None):
    body = {"approve": approve}
    if note is not None:
        body["note"] = note
    return await env.client.post(f"/api/investigation-chat-actions/{action_id}/decision", json=body)


async def row(env, model, **where):
    from sqlalchemy import select
    async with env.sessions() as db:
        q = select(model)
        for key, value in where.items():
            q = q.where(getattr(model, key) == value)
        return (await db.execute(q)).scalars().all()


async def tasks(env):
    return await row(env, env.models.AgentTask)


def _audit_actions(env):
    return [a[1] for a in env.audits]


# ─── decision mechanics ─────────────────────────────────────────

async def test_approve_isolate_runs_it_once_and_records_everything(act):
    agent = str(act.agents["blue-host"])
    aid = await propose(act, "isolate_host", {"agent_id": agent, "reason": "reverse shell"})
    r = await decide(act, aid, note="go")
    assert r.status_code == 200, r.text
    body = r.json()
    action = body["action"]
    assert action["status"] == "executed"
    assert action["decided_by"] == str(act.users["approver"])
    assert action["decided_at"] and action["executed_at"]
    [task] = await tasks(act)
    assert (task.task_type, task.params, str(task.agent_id)) == ("isolate_host", {}, agent)
    assert task.created_by == act.users["approver"]
    assert action["result"]["task_id"] == str(task.id)
    [agent_row] = await row(act, act.models.Agent, id=act.agents["blue-host"])
    assert agent_row.is_isolated is True

    # a system message with the outcome joins the conversation
    msg = body["message"]
    assert msg["role"] == "system" and "isolate_host" in msg["content"] and "boss" in msg["content"]
    [stored] = await row(act, act.models.InvestigationMessage, investigation_id=act.inv)
    assert stored.role == "system" and stored.content == msg["content"]

    # audit: approved then executed, naming requester, approver, target, result
    assert _audit_actions(act) == ["ai_chat_action_approved", "ai_chat_action_executed"]
    actor, _, resource, detail = act.audits[1]
    assert actor == act.users["approver"] and resource == str(aid)
    assert detail["requester"] == str(act.users["requester"]) and detail["approver"] == str(act.users["approver"])
    assert detail["target"] == agent and detail["result"]["task_id"] == str(task.id)

    # never twice: a retry / double click is 409 and changes nothing
    r = await decide(act, aid)
    assert r.status_code == 409
    r = await decide(act, aid, approve=False)
    assert r.status_code == 409
    assert len(await tasks(act)) == 1


async def test_reject_stores_the_decision_and_runs_nothing(act):
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    r = await decide(act, aid, approve=False, note="false positive")
    assert r.status_code == 200, r.text
    assert r.json()["action"]["status"] == "rejected"
    assert "false positive" in r.json()["message"]["content"]
    assert await tasks(act) == []
    assert _audit_actions(act) == ["ai_chat_action_rejected"]
    assert act.audits[0][3]["note"] == "false positive"
    assert (await decide(act, aid)).status_code == 409


async def test_permission_is_checked_on_the_approver_per_tool_class(act):
    iso = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    ioc = await propose(act, "add_case_ioc", {"type": "domain", "value": "evil.example", "reason": "C2"})
    act.user = _user(act.users["approver"], perms=CASE)
    r = await decide(act, iso)
    assert r.status_code == 403
    [still] = await row(act, act.models.InvestigationChatAction, id=iso)
    assert still.status == "proposed" and still.decided_by is None
    assert await tasks(act) == [] and act.audits == []
    # rejecting needs the same permission as approving
    assert (await decide(act, iso, approve=False)).status_code == 403

    r = await decide(act, ioc)
    assert r.status_code == 200, r.text
    assert r.json()["action"]["status"] == "executed"

    # endpoint-only approver can't decide case actions; superadmin can do anything
    ioc2 = await propose(act, "add_case_ioc", {"type": "ip", "value": "198.51.100.7", "reason": "C2"})
    act.user = _user(act.users["approver"], perms=ENDPOINT)
    assert (await decide(act, ioc2)).status_code == 403
    act.user = _user(act.users["approver"], perms=(), role="superadmin", group=None)
    assert (await decide(act, iso)).status_code == 200


async def test_other_group_cannot_see_or_decide(act):
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    act.user = _user(act.users["red"], group="red")
    assert (await decide(act, aid)).status_code == 404
    assert (await decide(act, uuid4())).status_code == 404
    [still] = await row(act, act.models.InvestigationChatAction, id=aid)
    assert still.status == "proposed"


async def test_proposals_expire_after_a_day(act):
    old = datetime.now(timezone.utc) - timedelta(hours=25)
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"},
                        created_at=old)
    r = await decide(act, aid)
    assert r.status_code == 409 and "expired" in r.json()["detail"]
    [stale] = await row(act, act.models.InvestigationChatAction, id=aid)
    assert stale.status == "expired"
    assert await tasks(act) == []

    # GET chat marks stale proposals expired too
    other = await propose(act, "pin_evidence", {"evidence_id": str(act.evidence)}, created_at=old)
    r = await act.client.get(f"/api/investigations/{act.inv}/chat")
    assert r.status_code == 200, r.text
    statuses = {a["id"]: a["status"] for a in r.json()["actions"]}
    assert statuses[str(other)] == "expired"


async def test_concurrent_decisions_execute_once(act):
    import asyncio
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    results = await asyncio.gather(*(decide(act, aid) for _ in range(4)))
    assert sorted(r.status_code for r in results) == [200, 409, 409, 409]
    assert len(await tasks(act)) == 1


async def test_failed_approval_by_a_real_session_user_is_recorded(act):
    """A failing executor rolls the request session back; the User loaded on it must not be read afterwards."""
    act.real_user = act.users["approver"]
    a = str(act.agents["blue-host"])
    off = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-off"]), "reason": "x"})
    private = await propose(act, "block_ip", {"agent_ids": [a], "ip": "10.0.0.5", "duration_seconds": 3600,
                                              "reason": "x"})
    allowed = await propose(act, "block_domain", {"domain": "raw.github.com", "reason": "x"})
    for aid in (off, private, allowed):
        r = await decide(act, aid)
        assert r.status_code == 200, r.text
        assert r.json()["action"]["status"] == "failed"
        assert "approver approved" in r.json()["message"]["content"]
    failed = [a for a in act.audits if a[1] == "ai_chat_action_failed"]
    assert [a[2] for a in failed] == [str(off), str(private), str(allowed)]
    assert all(a[0] == act.users["approver"] and a[3]["approver"] == str(act.users["approver"]) for a in failed)

    ok = await propose(act, "isolate_host", {"agent_id": a, "reason": "x"})
    assert (await decide(act, ok)).json()["action"]["status"] == "executed"
    no = await propose(act, "kill_process", {"agent_id": a, "pid": 5, "reason": "x"})
    assert (await decide(act, no, approve=False)).json()["action"]["status"] == "rejected"


async def test_unexpected_executor_error_is_an_unknown_outcome(act, monkeypatch):
    async def boom(run):
        raise RuntimeError("connection reset")

    monkeypatch.setitem(act.actions.EXECUTORS, "kill_process", boom)
    aid = await propose(act, "kill_process", {"agent_id": str(act.agents["blue-host"]), "pid": 5, "reason": "x"})
    r = await decide(act, aid)
    action = r.json()["action"]
    assert action["status"] == "failed"
    assert "outcome unknown" in action["error"] and "connection reset" in action["error"]
    assert "it may have been applied" in r.json()["message"]["content"]
    # a definite refusal stays a plain failure
    monkeypatch.setitem(act.actions.EXECUTORS, "kill_process", act.actions._kill_process)
    off = await propose(act, "kill_process", {"agent_id": str(act.agents["blue-off"]), "pid": 5, "reason": "x"})
    r = await decide(act, off)
    assert r.json()["action"]["status"] == "failed"
    assert "outcome unknown" not in r.json()["action"]["error"]


async def test_audit_failure_is_logged_with_its_detail(act, monkeypatch):
    calls = []

    async def broken(*a, **kw):
        raise RuntimeError("audit store down")

    monkeypatch.setattr(act.actions, "audit_log", broken)
    monkeypatch.setattr(act.actions.log, "error", lambda event, **kw: calls.append((event, kw)))
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed"
    events = [(e, kw["audit_action"]) for e, kw in calls]
    assert events == [("chat_action_audit_failed", "ai_chat_action_approved"),
                      ("chat_action_audit_failed", "ai_chat_action_executed")]
    assert calls[1][1]["detail"]["target"] == str(act.agents["blue-host"])
    assert "task_id" in calls[1][1]["detail"]["result"]


async def test_action_and_case_group_must_agree(act):
    from sqlalchemy import update
    aid = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-host"]), "reason": "x"})
    async with act.sessions() as db:
        await db.execute(update(act.models.InvestigationChatAction)
                         .where(act.models.InvestigationChatAction.id == aid).values(group_id="red"))
        await db.commit()
    act.user = _user(act.users["approver"], perms=(), role="superadmin", group=None)
    r = await decide(act, aid)
    assert r.status_code == 409
    [still] = await row(act, act.models.InvestigationChatAction, id=aid)
    assert still.status == "proposed" and await tasks(act) == []


# ─── endpoint executors ─────────────────────────────────────────

async def test_isolate_refuses_offline_and_other_group_agents(act):
    off = await propose(act, "isolate_host", {"agent_id": str(act.agents["blue-off"]), "reason": "x"})
    red = await propose(act, "isolate_host", {"agent_id": str(act.agents["red-host"]), "reason": "x"})
    gone = await propose(act, "isolate_host", {"agent_id": str(uuid4()), "reason": "x"})
    r = await decide(act, off)
    assert r.status_code == 200
    assert r.json()["action"]["status"] == "failed" and "not online" in r.json()["action"]["error"]
    assert "failed" in r.json()["message"]["content"]
    for aid in (red, gone):
        r = await decide(act, aid)
        assert r.json()["action"]["status"] == "failed"
        assert "not in this case's group" in r.json()["action"]["error"]
    assert await tasks(act) == []
    [red_agent] = await row(act, act.models.Agent, id=act.agents["red-host"])
    assert not red_agent.is_isolated
    assert _audit_actions(act).count("ai_chat_action_failed") == 3


async def test_unisolate_queues_the_task_and_clears_the_flag(act):
    async with act.sessions() as db:
        agent = await db.get(act.models.Agent, act.agents["blue-off"])
        agent.is_isolated = True
        await db.commit()
    aid = await propose(act, "unisolate_host", {"agent_id": str(act.agents["blue-off"]), "reason": "cleaned"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed", r.text
    [task] = await tasks(act)
    assert (task.task_type, task.params) == ("unisolate_host", {})
    [agent] = await row(act, act.models.Agent, id=act.agents["blue-off"])
    assert agent.is_isolated is False


async def test_kill_process_and_quarantine_file(act):
    agent = str(act.agents["blue-host"])
    kill = await propose(act, "kill_process", {"agent_id": agent, "pid": 4242, "reason": "nc"})
    quar = await propose(act, "quarantine_file", {"agent_id": agent, "path": "/tmp/.x/payload", "reason": "dropper"})
    off = await propose(act, "kill_process", {"agent_id": str(act.agents["blue-off"]), "pid": 1, "reason": "x"})
    assert (await decide(act, kill)).json()["action"]["status"] == "executed"
    assert (await decide(act, quar)).json()["action"]["status"] == "executed"
    r = await decide(act, off)
    assert r.json()["action"]["status"] == "failed" and "not online" in r.json()["action"]["error"]
    got = sorted((t.task_type, t.params) for t in await tasks(act))
    assert got == [("kill_process", {"pid": 4242}), ("quarantine_file", {"path": "/tmp/.x/payload"})]


async def test_quarantine_rechecks_the_path(act):
    from sqlalchemy import update
    aid = await propose(act, "quarantine_file", {"agent_id": str(act.agents["blue-host"]), "path": "/x",
                                                 "reason": "x"})
    async with act.sessions() as db:  # a row that slipped past the proposal check
        await db.execute(update(act.models.InvestigationChatAction).where(
            act.models.InvestigationChatAction.id == aid).values(params={"agent_id": str(act.agents["blue-host"]),
                                                                          "path": "relative/file"}))
        await db.commit()
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "failed" and "absolute" in r.json()["action"]["error"]
    assert await tasks(act) == []


async def test_block_ip_one_task_per_agent_in_the_case_group(act):
    a, b = str(act.agents["blue-host"]), str(act.agents["blue-off"])
    aid = await propose(act, "block_ip", {"agent_ids": [a, b], "ip": "45.33.32.156", "duration_seconds": 86400,
                                          "reason": "C2"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed", r.text
    got = sorted((str(t.agent_id), t.task_type, t.params) for t in await tasks(act))
    want = {"ip": "45.33.32.156", "duration_seconds": 86400, "case_id": str(act.case)}
    assert got == sorted([(a, "block_ip", want), (b, "block_ip", want)])
    assert len(r.json()["action"]["result"]["task_ids"]) == 2


async def test_block_ip_refusals(act):
    a = str(act.agents["blue-host"])
    private = await propose(act, "block_ip", {"agent_ids": [a], "ip": "10.0.0.5", "duration_seconds": 3600,
                                              "reason": "x"})
    red = await propose(act, "block_ip", {"agent_ids": [a, str(act.agents["red-host"])], "ip": "45.33.32.156",
                                          "duration_seconds": 3600, "reason": "x"})
    r = await decide(act, private)
    assert r.json()["action"]["status"] == "failed" and "public" in r.json()["action"]["error"]
    r = await decide(act, red)
    assert r.json()["action"]["status"] == "failed" and "not in this case's group" in r.json()["action"]["error"]
    assert await tasks(act) == []


def test_block_ip_proposal_allows_at_most_20_agents():
    from app.services import investigation_chat_actions as actions
    ctx = actions.ChatCtx(uuid4(), uuid4(), "blue", None)
    with pytest.raises(actions.ProposalError):
        actions.validate_proposal("block_ip", {"agent_ids": [str(uuid4()) for _ in range(21)], "ip": "8.8.8.8",
                                               "duration_seconds": 3600, "reason": "x"}, ctx)


async def test_block_domain_goes_through_web_protection(act):
    aid = await propose(act, "block_domain", {"domain": "https://Evil.Example/login", "reason": "C2 domain",
                                              "days": 7})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed", r.text
    [entry] = await row(act, act.models.WebBlockEntry)
    assert (entry.domain, entry.group_id, entry.source, entry.status) == ("evil.example", "blue", "manual", "active")
    assert entry.reason == "AI chat: C2 domain"
    assert entry.created_by == act.users["approver"]
    left = entry.expires_at - datetime.now(timezone.utc)
    assert timedelta(days=6, hours=23) < left <= timedelta(days=7)
    assert r.json()["action"]["result"]["domain"] == "evil.example"
    assert "web_block.add" in _audit_actions(act)

    allowed = await propose(act, "block_domain", {"domain": "raw.github.com", "reason": "x"})
    r = await decide(act, allowed)
    assert r.json()["action"]["status"] == "failed" and "allowlisted" in r.json()["action"]["error"]
    bad = await propose(act, "block_domain", {"domain": "45.33.32.156", "reason": "x"})
    r = await decide(act, bad)
    assert r.json()["action"]["status"] == "failed"
    assert len(await row(act, act.models.WebBlockEntry)) == 1


async def test_run_live_response_schedules_a_flow_and_get_resolves_it(act):
    agent = str(act.agents["blue-host"])
    aid = await propose(act, "run_live_response", {"agent_id": agent, "artifact": "Linux.Sys.Pslist",
                                                   "params": {"ProcessRegex": "nc"}, "reason": "who else"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed", r.text
    [flow] = await row(act, act.models.Flow)
    assert (str(flow.agent_id), flow.artifact, flow.params["ProcessRegex"]) == (agent, "Linux.Sys.Pslist", "nc")
    assert flow.created_by == act.users["approver"]
    assert r.json()["action"]["result"]["flow_id"] == str(flow.id)
    assert act.redis.kv  # the agent was woken

    async with act.sessions() as db:
        f = await db.get(act.models.Flow, flow.id)
        f.status, f.total_rows = "finished", 12
        await db.commit()
    r = await act.client.get(f"/api/investigations/{act.inv}/chat")
    [action] = [a for a in r.json()["actions"] if a["id"] == str(aid)]
    assert action["result"]["flow_status"] == "finished" and action["result"]["flow_rows"] == 12


async def test_run_live_response_refusals(act):
    a = str(act.agents["blue-host"])
    unknown = await propose(act, "run_live_response", {"agent_id": a, "artifact": "No.Such.Thing", "reason": "x"})
    off = await propose(act, "run_live_response", {"agent_id": str(act.agents["blue-off"]),
                                                   "artifact": "Linux.Sys.Pslist", "reason": "x"})
    red = await propose(act, "run_live_response", {"agent_id": str(act.agents["red-host"]),
                                                   "artifact": "Linux.Sys.Pslist", "reason": "x"})
    secret = await propose(act, "run_live_response", {"agent_id": a, "artifact": "Generic.Collectors.File",
                                                      "params": {"Path": "/etc/shadow"}, "reason": "x"})
    old = await propose(act, "run_live_response", {"agent_id": str(act.agents["blue-old"]),
                                                   "artifact": "Linux.Sys.Pslist", "reason": "x"})
    async with act.sessions() as db:  # another investigation's unpromoted AI artifact
        db.add(act.models.FlowArtifact(name="AI.Other", content="name: AI.Other\nsources:\n  - name: P\n    plugin: pslist\n",
                                       group_id="blue", created_by_investigation_id=uuid4()))
        await db.commit()
    ai = await propose(act, "run_live_response", {"agent_id": a, "artifact": "AI.Other", "reason": "x"})
    expect = {unknown: "not found", off: "not online", red: "not in this case's group", secret: "credentials",
              old: "flow runner", ai: "not promoted"}
    for aid, words in expect.items():
        r = await decide(act, aid)
        assert r.json()["action"]["status"] == "failed", (words, r.text)
        assert words in r.json()["action"]["error"], (words, r.json()["action"]["error"])
    assert await row(act, act.models.Flow) == []


# ─── case and Threat IoC executors ──────────────────────────────

async def test_pin_evidence_only_from_this_investigation(act):
    aid = await propose(act, "pin_evidence", {"evidence_id": str(act.evidence)})
    assert (await decide(act, aid)).json()["action"]["status"] == "executed"
    [ev] = await row(act, act.models.InvestigationEvidence, id=act.evidence)
    assert ev.pinned is True
    other = await propose(act, "pin_evidence", {"evidence_id": str(act.other_evidence)})
    r = await decide(act, other)
    assert r.json()["action"]["status"] == "failed" and "not found" in r.json()["action"]["error"]
    [ev] = await row(act, act.models.InvestigationEvidence, id=act.other_evidence)
    assert ev.pinned is False


async def test_add_and_remove_case_iocs_normalised(act):
    add = await propose(act, "add_case_ioc", {"type": "domain", "value": "Evil.Example.", "reason": "C2"})
    dup = await propose(act, "add_case_ioc", {"type": "ip", "value": "203.0.113.9", "reason": "dup"})
    bad = await propose(act, "add_case_ioc", {"type": "sha256", "value": "not-a-hash", "reason": "x"})
    assert (await decide(act, add)).json()["action"]["result"]["ioc_key"] == "domain:evil.example"
    r = await decide(act, dup)
    assert r.json()["action"]["status"] == "executed" and r.json()["action"]["result"]["added"] is False
    r = await decide(act, bad)
    assert r.json()["action"]["status"] == "failed" and "sha256" in r.json()["action"]["error"]
    [case] = await row(act, act.models.Case, id=act.case)
    assert case.ioc_data["ioc_keys"] == ["domain:evil.example", "ip:203.0.113.9"]
    assert case.ioc_data["affected_hosts"] == ["blue-host"]  # the rest of ioc_data is kept

    rm = await propose(act, "remove_case_ioc", {"type": "ip", "value": "203.0.113.9", "reason": "benign"})
    r = await decide(act, rm)
    assert r.json()["action"]["status"] == "executed", r.text
    [case] = await row(act, act.models.Case, id=act.case)
    assert case.ioc_data["ioc_keys"] == ["domain:evil.example"]
    # the case-scoped Threat IoC doc is deleted too (alert-derived ones are not)
    want = hashlib.sha1(f"case:{act.case}|ip|203.0.113.9".encode()).hexdigest()
    assert act.es_delete == [want]


def test_url_iocs_use_an_ascii_host_like_the_worker():
    from app.services.investigation_chat_actions import normalize_ioc
    assert normalize_ioc("url", "HTTPS://Bücher.Example/Path?q=1") == "https://xn--bcher-kva.example/path?q=1"
    assert normalize_ioc("url", "http://45.33.32.156:8080/x") == "http://45.33.32.156:8080/x"


async def test_add_threat_ioc_writes_the_case_scoped_doc(act):
    aid = await propose(act, "add_threat_ioc", {"type": "domain", "value": "C2.Evil.Example", "reason": "beacon"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "executed", r.text
    [(doc_id, doc)] = act.es_index
    assert doc_id == hashlib.sha1(f"case:{act.case}|domain|c2.evil.example".encode()).hexdigest()
    created = datetime.fromisoformat(doc.pop("created_at"))
    assert abs(datetime.now(timezone.utc) - created) < timedelta(minutes=1)
    assert doc == {"alert_id": f"case:{act.case}", "group_id": "blue", "type": "domain", "value": "c2.evil.example",
                   "ioc_key": "domain:c2.evil.example", "severity": "critical", "severity_rank": 4,
                   "hostname": "blue-host", "agent_id": str(act.agents["blue-host"]),
                   "rule_title": "Added from investigation chat", "ai_verdict": None, "origin": "analyst"}
    assert r.json()["action"]["result"]["doc_id"] == doc_id


async def test_threat_ioc_failure_is_recorded(act):
    act.es_fail = "connection refused"
    aid = await propose(act, "add_threat_ioc", {"type": "ip", "value": "198.51.100.7", "reason": "x"})
    r = await decide(act, aid)
    assert r.json()["action"]["status"] == "failed" and "connection refused" in r.json()["action"]["error"]
    assert _audit_actions(act) == ["ai_chat_action_approved", "ai_chat_action_failed"]


# ─── es_client write helpers ────────────────────────────────────

class _FakeES:
    def __init__(self, exists=True, delete_status=200):
        self.calls, self.exists, self.delete_status = [], exists, delete_status

    async def head(self, path):
        self.calls.append(("HEAD", path))
        return SimpleNamespace(status_code=200 if self.exists else 404)

    async def put(self, path, json=None, params=None):
        self.calls.append(("PUT", path, json, params))
        return SimpleNamespace(status_code=201, raise_for_status=lambda: None)

    async def delete(self, path, params=None):
        self.calls.append(("DELETE", path, params))

        def check():
            if self.delete_status >= 400 and self.delete_status != 404:
                raise RuntimeError(self.delete_status)
        return SimpleNamespace(status_code=self.delete_status, raise_for_status=check)


async def test_es_index_and_delete_ioc(monkeypatch):
    from app.core import es_client
    fake = _FakeES(exists=False)
    monkeypatch.setattr(es_client, "_get_client", lambda: fake)
    await es_client.index_ioc("abc", {"value": "x"})
    assert fake.calls[0] == ("HEAD", "/alert_iocs")
    method, path, body, _ = fake.calls[1]
    assert (method, path) == ("PUT", "/alert_iocs")
    assert body["mappings"]["properties"]["severity_rank"] == {"type": "byte"}
    assert fake.calls[2][:3] == ("PUT", "/alert_iocs/_doc/abc", {"value": "x"})
    assert await es_client.delete_ioc("abc") is True
    assert fake.calls[-1][:2] == ("DELETE", "/alert_iocs/_doc/abc")
    fake.delete_status = 404
    assert await es_client.delete_ioc("abc") is False
