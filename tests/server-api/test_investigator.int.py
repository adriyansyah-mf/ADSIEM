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
from types import SimpleNamespace

import pytest
import httpx

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
        # scripts that take a third argument also see the conversation (context, analyst notes, repair prompts)
        wants_messages = self.script.__code__.co_argcount == 3
        step = self.script(len(self.seen), results, messages) if wants_messages else self.script(len(self.seen), results)
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
            # a fresh schema: the worker's tests share this database and leave tables
            # (e.g. case_embeddings → cases) these models don't know
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield
    _run(engine.dispose())


def _seed(hostname="web01"):
    from app.core.database import AsyncSessionLocal
    from app.models.models import Agent, Alert, Case, PlatformSetting, Role, User

    async def go():
        async with AsyncSessionLocal() as db:
            role = Role(name=f"analyst-{uuid.uuid4().hex[:6]}")
            db.add(role)
            await db.flush()
            user = User(username=f"ana-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex}@x", password_hash="x",
                        role_id=role.id, group_id="blue")
            agent = Agent(name=hostname, hostname=hostname, group_id="blue", token_hash=uuid.uuid4().hex,
                          status="online", last_seen_at=datetime.now(timezone.utc),
                          flow_poll_at=datetime.now(timezone.utc))
            db.add_all([user, agent])
            await db.flush()
            alert = Alert(title="Reverse shell from /tmp", severity="high", group_id="blue",
                          hostname=hostname, agent_id=agent.id, source_ip="203.0.113.9")
            db.add(alert)
            await db.flush()
            case = Case(title="web01 compromise?", severity="high", group_id="blue", alert_id=alert.id)
            db.add(case)
            # set, not just present: _seed_settings() seeds it empty, and a resumed run needs a provider
            await db.merge(PlatformSetting(key="ninerouter_api_key", value="test-key", is_secret=True))
            await db.commit()
            return user.id, agent.id, case.id
    return _run(go())


def test_malwarebazaar_defaults_require_opt_in_and_mask_the_key(env):
    from app.api.routes.settings import _mask, SECRET_MASK
    from app.core.database import AsyncSessionLocal
    from app.main import _seed_settings
    from app.models.models import PlatformSetting

    # Given the fresh schema, when normal API startup seeds settings.
    _run(_seed_settings())

    async def check():
        async with AsyncSessionLocal() as db:
            enabled = await db.get(PlatformSetting, "malwarebazaar_enabled")
            key = await db.get(PlatformSetting, "malwarebazaar_api_key")
            # Then external queries need explicit opt-in, and a saved key is masked.
            assert enabled.value == "false"
            assert key.is_secret is True
            key.value = "dummy-key-never-contact-provider"
            assert _mask(key).value == SECRET_MASK
    _run(check())


@pytest.mark.parametrize("provider_status, expected, collect_first", [
    (200, "found", False), (200, "found", True),
    (503, "unavailable", False), (0, "unobserved_hash", False), (-1, "unobserved_hash", False),
])
def test_ai_selects_hash_lookup_and_records_evidence(env, monkeypatch, provider_status, expected, collect_first):
    """Real investigator loop, scoped case context and persisted evidence; fake SaaS wire."""
    from app.core.database import AsyncSessionLocal
    from app.models.models import Alert, Case, PlatformSetting

    # Given a hash already in this case's alert and enabled metadata-only lookup.
    hostname = f"mb-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(hostname)
    h = ("c" if collect_first else "a") * 64
    artifact = f"AI.Test.Hash{uuid.uuid4().hex[:8]}"

    async def setup():
        async with AsyncSessionLocal() as db:
            case = await db.get(Case, case_id)
            alert = await db.get(Alert, case.alert_id)
            alert.context = {} if collect_first else {"file": {"hash": {"sha256": h}}}
            for key, value in [("malwarebazaar_enabled", "true"), ("malwarebazaar_api_key", "test-key")]:
                await db.merge(PlatformSetting(key=key, value=value, is_secret=key.endswith("api_key")))
            await db.commit()
    _run(setup())
    requests = []

    async def respond(request):
        requests.append(request)
        return httpx.Response(provider_status, json={"query_status": "ok", "data": [{
            "sha256_hash": h, "signature": "ExampleFamily", "tags": ["trojan"],
        }]})
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request",
                        lambda self, request: transport.handle_async_request(request))

    def script(turn, results):
        if provider_status == -1:
            if turn == 1:
                return ("pivot_ioc", {"ioc": "b" * 64})
            if turn == 2:
                return ("lookup_malwarebazaar", {"hash_value": "b" * 64,
                                                 "reason": "An echoed query is not evidence"})
            assert results[-1]["status"] == expected
            return f"## Evidence\nMalwareBazaar: {expected}\nVERDICT: inconclusive"
        if collect_first:
            if turn == 1:
                assert requests == []
                return ("create_artifact", {"yaml_text": f"name: {artifact}\nsources:\n"
                        "  - name: Hashes\n    plugin: hash\n    args:\n      globs: [/tmp/suspect]\n"})
            if turn == 2:
                return ("run_artifact", {"artifact": artifact, "host": hostname, "reason": "Hash suspicious file"})
            if turn == 3:
                assert results[-1]["sources"][0]["rows"][0]["SHA256"] == h
                return ("lookup_malwarebazaar", {"hash_value": h, "reason": "Validate collected hash"})
            assert results[-1]["status"] == expected
            return f"## Evidence\nMalwareBazaar: {expected} for {h}\nVERDICT: inconclusive"
        if turn == 1:
            assert requests == []  # Context loading never queries the external provider.
            return ("lookup_malwarebazaar", {"hash_value": "b" * 64 if provider_status == 0 else h,
                                             "reason": "Validate suspicious file"})
        assert results[-1]["status"] == expected
        return f"## Evidence\nMalwareBazaar: {expected} for {h}\nVERDICT: inconclusive"

    # When the AI elects to call the new tool (no automatic lookup in context loading).
    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    # Then the provider result reaches both the model and the persisted case evidence.
    assert "lookup_malwarebazaar" in model.tool_names
    assert inv.status == "finished"
    assert expected in inv.report
    evidence = [s for s in inv.steps if s["kind"] == "enrichment"]
    assert evidence[0]["result"]["status"] == expected
    assert evidence[0]["result"]["queried_hash"] == ("b" * 64 if provider_status <= 0 else h)
    assert "test-key" not in json.dumps(evidence)
    assert len(requests) == (0 if provider_status <= 0 else 1)


def test_disabled_enrichment_does_not_contact_the_provider(env, monkeypatch):
    from app.core.database import AsyncSessionLocal
    from app.models.models import PlatformSetting

    # Given enrichment is disabled by the administrator.
    user_id, _, case_id = _seed(f"mb-{uuid.uuid4().hex[:8]}")

    async def setup():
        async with AsyncSessionLocal() as db:
            await db.merge(PlatformSetting(key="malwarebazaar_enabled", value="false"))
            await db.commit()
    _run(setup())

    async def reject_request(request):
        pytest.fail("disabled enrichment must not contact an external provider")
    transport = httpx.MockTransport(reject_request)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request",
                        lambda self, request: transport.handle_async_request(request))

    def script(turn, results):
        if turn == 1:
            return ("lookup_malwarebazaar", {"hash_value": "a" * 64, "reason": "Check suspicious file"})
        assert results[-1]["status"] == "disabled"
        return "## Gaps\nProvider disabled.\nVERDICT: inconclusive"

    # When a model nevertheless asks for a lookup.
    inv, _ = _investigate(script, monkeypatch, user_id, case_id)
    # Then the investigation completes without changing that policy.
    assert inv.status == "finished"
    assert any(s["kind"] == "enrichment" and s["result"]["status"] == "disabled" for s in inv.steps)


async def _fake_agent(stop: asyncio.Event):
    """Answer every scheduled flow like an agent: rows for pslist, finished."""
    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.models.models import Flow, FlowRowBatch

    while not stop.is_set():
        async with AsyncSessionLocal() as db:
            for flow in (await db.execute(select(Flow).where(Flow.status == "scheduled"))).scalars().all():
                for src in flow.request["sources"]:
                    if src["plugin"] == "hash":
                        db.add(FlowRowBatch(flow_id=flow.id, source=src["name"], rows=[
                            {"Path": "/tmp/suspect", "Size": 123, "SHA256": "c" * 64},
                        ]))
                    if src["plugin"] == "exec":
                        line = " ".join([src["args"]["command"], *src["args"]["args"]])
                        db.add(FlowRowBatch(flow_id=flow.id, source=src["name"], rows=[
                            {"Stream": "stdout", "Line": 1, "Text": f"ran: {line}"},
                            {"Stream": "exit", "Line": 0, "Text": "exit code 0 after 3 ms", "ExitCode": 0},
                        ]))
                    if src["plugin"] == "pslist":
                        db.add(FlowRowBatch(flow_id=flow.id, source=src["name"], rows=[
                            {"Pid": 4242, "Name": "kworkerd", "Exe": "/tmp/.x/kworkerd", "CommandLine": "kworkerd -c 203.0.113.9:443"},
                        ]))
                await db.execute(update(Flow).where(Flow.id == flow.id).values(status="finished", total_rows=1))
            await db.commit()
        await asyncio.sleep(0.5)


def _investigate(script, monkeypatch, user_id, case_id, cancel_after=None, setup=None):
    """Run one investigation with a scripted model; `setup(inv_id)` (async) runs
    first, e.g. to queue analyst actions or start an approver."""
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
        if setup:
            await setup(inv_id)
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


# ─── Ledger (investigation_ledger.py, spec Phase 1a) ─────────────

def _analyst(user_id):
    """A superadmin calling the routes directly."""
    return SimpleNamespace(id=user_id, username="ana", group_id="blue",
                           role=SimpleNamespace(name="superadmin", permissions=[]))


def _context(messages) -> dict:
    """The case context the model was shown in its first prompt."""
    return json.loads(messages[1].content.split("Context:\n", 1)[1])


def _rows(model, inv_id):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(model).where(model.investigation_id == inv_id)
                                     .order_by(model.created_at))).scalars().all()
    return _run(go())


def test_ledger_records_actions_evidence_and_a_cited_report(env, monkeypatch):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseNote, InvestigationAction, InvestigationEvidence, InvestigationHypothesis

    host = f"led-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(host)
    st = {}

    def report(claims):
        return json.dumps({"verdict": "true_positive", "confidence": 90, "executive_summary": "A miner runs from /tmp.",
                           "claims": claims, "recommended_actions": ["Isolate the host"], "gaps": []})

    def script(turn, results, messages):
        if turn == 1:
            return ("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": host, "reason": "what runs"})
        if turn == 2:
            st["flow"] = results[-1]["sources"][0]["evidence_id"]
            return ("record_hypothesis", {"statement": "A miner runs from /tmp", "state": "supported",
                                          "confidence": 85, "supporting_evidence_ids": [st["flow"]]})
        if turn == 3:
            assert results[-1]["state"] == "supported"
            # the same collection, host spelled differently: endpoint work never repeats
            return ("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": host.upper(), "reason": "again"})
        if turn == 4:
            assert "already ran as action #1" in results[-1]["error"]
            st["alert"] = _context(messages)["alerts"][0]["evidence_id"]
            return report([
                {"id": "c1", "section": "analysis", "text": "kworkerd runs from /tmp/.x", "evidence_ids": [st["flow"]]},
                {"id": "c2", "section": "timeline", "text": "The reverse-shell alert fired", "evidence_ids": [st["alert"]]},
                {"id": "c3", "section": "iocs", "text": "203.0.113.9", "evidence_ids": ["made-up"]},
            ])
        if turn == 5:  # one repair attempt, told exactly what failed
            assert "claim c3 (iocs): made-up is not evidence from this investigation" in messages[-1].content
            return report([
                {"id": "c1", "section": "analysis", "text": "kworkerd runs from /tmp/.x", "evidence_ids": [st["flow"]]},
                {"id": "c2", "section": "timeline", "text": "The reverse-shell alert fired", "evidence_ids": [st["alert"]]},
                {"id": "c3", "section": "iocs", "text": "203.0.113.9 (kworkerd command line)", "evidence_ids": [st["flow"]]},
            ])
        raise AssertionError(f"unexpected turn {turn}")

    inv, _ = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished", inv.error
    assert inv.verdict == "true_positive" and inv.phase is None
    assert inv.report_json["unverified_claims"] == 0 and all(c["verified"] for c in inv.report_json["claims"])
    assert "kworkerd runs from /tmp/.x [E1]" in inv.report and "Unverified" not in inv.report
    assert any(s["kind"] == "report_check" for s in inv.steps)

    actions = sorted(_rows(InvestigationAction, inv.id), key=lambda a: a.ordinal)
    assert [(a.tool, a.status, a.risk_tier, a.source) for a in actions] == [
        ("run_artifact", "completed", 1, "planner"), ("record_hypothesis", "completed", 0, "planner")]
    assert actions[0].result_ref["evidence_ids"] == [st["flow"]] and actions[0].result_ref["flow_id"]
    evidence = {str(e.id): e for e in _rows(InvestigationEvidence, inv.id)}
    assert evidence[st["alert"]].evidence_type == "alert" and evidence[st["flow"]].evidence_type == "flow_row"
    [hyp] = _rows(InvestigationHypothesis, inv.id)
    assert (hyp.state, hyp.confidence, hyp.supporting_evidence_ids) == ("supported", 85, [st["flow"]])

    async def note():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(CaseNote.content).where(CaseNote.case_id == case_id))).scalar_one()
    assert "[E1]" in _run(note())


def test_a_verdict_resting_on_unverified_claims_is_downgraded(env, monkeypatch):
    user_id, _, case_id = _seed(f"led-{uuid.uuid4().hex[:8]}")
    bad = json.dumps({"verdict": "true_positive", "confidence": 70, "executive_summary": "Compromised.",
                      "claims": [{"id": "c1", "section": "analysis", "text": "Ransomware encrypted /srv",
                                  "evidence_ids": ["nothing"]}]})

    def script(turn, results):
        return bad if turn <= 2 else "unexpected"  # the repair repeats the same claim

    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished" and len(model.seen) == 2
    assert inv.verdict == "inconclusive" and inv.report_json["verdict_downgraded_from"] == "true_positive"
    assert "## Unverified statements" in inv.report and "⚠ Ransomware encrypted /srv" in inv.report


def test_analyst_actions_run_between_rounds_and_skips_hold(env, monkeypatch):
    from app.core.database import AsyncSessionLocal
    from app.models.models import InvestigationAction
    from app.services import investigation_ledger as ledger

    host = f"led-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(host)

    async def setup(inv_id):
        async with AsyncSessionLocal() as db:
            for ordinal, artifact, status in ((1, "Linux.Sys.Pslist", "queued"), (2, "Linux.Network.Netstat", "skipped")):
                params = {"artifact": artifact}
                db.add(InvestigationAction(
                    investigation_id=inv_id, group_id="blue", ordinal=ordinal, kind="artifact", tool="run_artifact",
                    target=host, params=params, reason="analyst wants it", risk_tier=1, status=status,
                    source="analyst", dependencies=[], idempotency_key=ledger.idempotency_key("run_artifact", host, params),
                    result_ref={}, attempts=0, decision_note="not needed" if status == "skipped" else None))
            await db.commit()

    def script(turn, results, messages):
        if turn == 1:
            # the analyst's pslist ran before the model's first move, as its own tool call
            assert "An analyst added action #1 (run_artifact)" in messages[-3].content
            assert results[-1]["sources"][0]["rows"][0]["Exe"] == "/tmp/.x/kworkerd"
            return ("run_artifact", {"artifact": "Linux.Network.Netstat", "host": host})
        if turn == 2:
            assert "skipped or rejected this exact action (#2) (not needed)" in results[-1]["error"]
            return "## Summary\nThe analyst's pslist shows a miner.\nVERDICT: true_positive"
        raise AssertionError(f"unexpected turn {turn}")

    inv, _ = _investigate(script, monkeypatch, user_id, case_id, setup=setup)
    assert inv.status == "finished", inv.error
    assert inv.report_json == {"citations_unchecked": True}  # a Markdown report: kept, but not citation-checked
    rows = {a.ordinal: a for a in _rows(InvestigationAction, inv.id)}
    assert (rows[1].status, rows[1].source) == ("completed", "analyst") and rows[1].result_ref["evidence_ids"]
    assert rows[2].status == "skipped" and len(rows) == 2


def _approver(inv_id, user_id, approve, seen, note=None):
    """Decide the first action the policy holds, through the route, like an analyst in the UI."""
    from fastapi import BackgroundTasks
    from sqlalchemy import select

    from app.api.routes import investigations as routes
    from app.core.database import AsyncSessionLocal
    from app.models.models import InvestigationAction

    async def go():
        while True:
            async with AsyncSessionLocal() as db:
                row = (await db.execute(select(InvestigationAction).where(
                    InvestigationAction.investigation_id == inv_id,
                    InvestigationAction.status == "awaiting_approval"))).scalars().first()
                if row is not None:
                    seen.append(row.approval_reason)
                    await routes.decide_action(row.id, routes.CommandDecision(approve=approve, note=note),
                                               BackgroundTasks(), db=db, user=_analyst(user_id), group_filter="blue")
                    return
            await asyncio.sleep(0.3)
    return asyncio.create_task(go())


def test_another_runs_ai_artifact_waits_for_an_analyst(env, monkeypatch):
    from app.core.database import AsyncSessionLocal
    from app.models.models import FlowArtifact, InvestigationAction

    host = f"led-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(host)
    name = f"AI.Linux.Foreign{uuid.uuid4().hex[:6]}"
    seen: list = []
    tasks: list = []

    async def setup(inv_id):
        async with AsyncSessionLocal() as db:
            db.add(FlowArtifact(name=name, content=TMP_ARTIFACT.replace("AI.Linux.TmpProcs", name), group_id="blue",
                                created_by_investigation_id=uuid.uuid4()))
            await db.commit()
        tasks.append(_approver(inv_id, user_id, True, seen))

    def script(turn, results):
        if turn == 1:
            return ("list_artifacts", {"os": "linux"})
        if turn == 2:
            assert name not in {a["name"] for a in results[-1]["artifacts"]}  # not offered for reuse
            return ("run_artifact", {"artifact": name, "host": host, "reason": "reuse an earlier collector"})
        if turn == 3:
            assert results[-1]["status"] == "finished"
            return "## Summary\nRan after approval.\nVERDICT: inconclusive"
        raise AssertionError(f"unexpected turn {turn}")

    inv, _ = _investigate(script, monkeypatch, user_id, case_id, setup=setup)
    assert inv.status == "finished", inv.error
    assert "written by another AI investigation" in seen[0]
    row = next(a for a in _rows(InvestigationAction, inv.id) if a.tool == "run_artifact")
    assert row.status == "completed" and row.decided_by == user_id
    kinds = [s["kind"] for s in inv.steps]
    assert "approval_needed" in kinds and any(s["kind"] == "action_decision" and s["status"] == "approved" for s in inv.steps)


def test_a_host_over_its_automatic_budget_needs_approval(env, monkeypatch):
    from app.models.models import InvestigationAction
    from app.services import investigation_ledger as ledger

    monkeypatch.setattr(ledger, "HOST_AUTO_FLOWS", 1)
    host = f"led-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(host)
    seen: list = []

    async def setup(inv_id):
        _approver(inv_id, user_id, False, seen, note="enough for this host")

    def script(turn, results):
        if turn == 1:
            return ("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": host})
        if turn == 2:
            return ("run_artifact", {"artifact": "Linux.Network.Netstat", "host": host})
        if turn == 3:
            assert "did not approve this action (enough for this host)" in results[-1]["error"]
            return ("run_artifact", {"artifact": "Linux.Network.Netstat", "host": host})
        if turn == 4:
            assert "skipped or rejected" in results[-1]["error"]
            return "## Summary\nStopped at the host budget.\nVERDICT: inconclusive"
        raise AssertionError(f"unexpected turn {turn}")

    inv, _ = _investigate(script, monkeypatch, user_id, case_id, setup=setup)
    assert inv.status == "finished", inv.error
    assert "automatic collections on the host" in seen[0]
    statuses = {a.params["artifact"]: a.status for a in _rows(InvestigationAction, inv.id)}
    assert statuses == {"Linux.Sys.Pslist": "completed", "Linux.Network.Netstat": "skipped"}


def test_promoting_an_ai_artifact_lets_other_runs_reuse_it(env):
    from fastapi import BackgroundTasks, HTTPException

    from app.api.routes import flows
    from app.core.database import AsyncSessionLocal
    from app.models.models import FlowArtifact
    from app.services import investigator

    name = f"AI.Linux.Promote{uuid.uuid4().hex[:6]}"
    user_id, _, _ = _seed(f"led-{uuid.uuid4().hex[:8]}")
    other_run = SimpleNamespace(inv_id=uuid.uuid4())

    async def go():
        async with AsyncSessionLocal() as db:
            row = FlowArtifact(name=name, content=TMP_ARTIFACT.replace("AI.Linux.TmpProcs", name), group_id="blue",
                               created_by_investigation_id=uuid.uuid4())
            db.add(row)
            await db.commit()
            assert not investigator._reusable(row, other_run)
            for who, group in ((name, "red"), ("Linux.Sys.Pslist", "blue")):  # other group; not an AI artifact
                try:
                    await flows.promote_flow_artifact(who, BackgroundTasks(), db=db, user=_analyst(user_id),
                                                      group_filter=group)
                    raise AssertionError("expected 404")
                except HTTPException as exc:
                    assert exc.status_code == 404
            out = await flows.promote_flow_artifact(name, BackgroundTasks(), db=db, user=_analyst(user_id),
                                                    group_filter="blue")
            assert out["promoted_at"] is not None
            await db.refresh(row)
            assert row.promoted_by == user_id and investigator._reusable(row, other_run)
    _run(go())


def test_queue_routes_check_scope_state_and_duplicates(env):
    from fastapi import BackgroundTasks, HTTPException

    from app.api.routes import investigations as routes
    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation, InvestigationAction
    from app.services import investigation_ledger as ledger

    host = f"led-{uuid.uuid4().hex[:8]}"
    user_id, _, case_id = _seed(host)
    user = _analyst(user_id)

    async def go():
        async with AsyncSessionLocal() as db:
            inv = CaseInvestigation(case_id=case_id, group_id="blue", started_by=user_id, status="running", steps=[])
            db.add(inv)
            await db.commit()

            async def call(fn, *args, group="blue", **kw):
                return await fn(*args, db=db, group_filter=group, **kw)

            async def status_of(fn, *args, **kw):
                try:
                    await call(fn, *args, **kw)
                except HTTPException as exc:
                    return exc.status_code
                return 200

            add = routes.ActionIn
            assert await status_of(routes.add_action, case_id, inv.id, add(tool="run_command"), BackgroundTasks(), user=user) == 422
            assert await status_of(routes.add_action, case_id, inv.id, add(tool="run_artifact", params={"artifact": "X"}),
                                   BackgroundTasks(), user=user) == 422  # no host
            row = await call(routes.add_action, case_id, inv.id,
                             add(tool="run_artifact", host=host, params={"artifact": "Linux.Sys.Pslist"}, reason="look"),
                             BackgroundTasks(), user=user)
            assert (row.status, row.source, row.risk_tier) == ("queued", "analyst", 1)
            assert await status_of(routes.add_action, case_id, inv.id,
                                   add(tool="run_artifact", host=host.upper(), params={"artifact": "Linux.Sys.Pslist"}),
                                   BackgroundTasks(), user=user) == 409  # the same operation
            assert await status_of(routes.add_action, case_id, inv.id,
                                   add(tool="search_events", params={"query": "x"}, dependencies=[uuid.uuid4()]),
                                   BackgroundTasks(), user=user) == 422  # unknown dependency
            assert await status_of(routes.list_actions, case_id, inv.id, _=user, group="red") == 404

            skipped = await call(routes.skip_action, row.id, BackgroundTasks(), user=user)
            assert skipped.status == "skipped" and skipped.decided_by == user_id
            assert await status_of(routes.skip_action, row.id, BackgroundTasks(), user=user) == 409

            cmd = InvestigationAction(investigation_id=inv.id, group_id="blue", ordinal=9, kind="command",
                                      tool="run_command", risk_tier=2, status="awaiting_approval", source="planner",
                                      idempotency_key="k" * 64, params={}, dependencies=[], result_ref={}, attempts=1)
            db.add(cmd)
            await db.commit()
            assert await status_of(routes.decide_action, cmd.id, routes.CommandDecision(approve=True),
                                   BackgroundTasks(), user=user) == 409  # commands have their own decision route

            ev_id = await ledger.record_evidence(db, investigation_id=inv.id, group_id="blue", action_id=None,
                                                 spec=ledger.EvidenceSpec("event", "siem_query", "q", "t", "s", {"a": 1}))
            await db.commit()
            pinned = await call(routes.pin_evidence, ev_id, routes.PinIn(pinned=True), BackgroundTasks(), user=user)
            assert pinned.pinned
            assert await status_of(routes.pin_evidence, ev_id, routes.PinIn(), BackgroundTasks(), user=user, group="red") == 404

            h = await call(routes.add_hypothesis, case_id, inv.id, routes.HypothesisIn(statement="Benign admin script"),
                           BackgroundTasks(), user=user)
            assert h.source == "analyst"
            assert await status_of(routes.update_hypothesis, h.id, routes.HypothesisUpdate(state="supported"),
                                   BackgroundTasks(), user=user) == 422  # no evidence
            h = await call(routes.update_hypothesis, h.id,
                           routes.HypothesisUpdate(state="supported", supporting_evidence_ids=[str(ev_id)]),
                           BackgroundTasks(), user=user)
            assert h.state == "supported"

            raised = await call(routes.raise_budget, inv.id, routes.BudgetIn(flows=4), BackgroundTasks(), user=user)
            assert raised.budget_overrides["flows"] == 4
            assert await status_of(routes.raise_budget, inv.id, routes.BudgetIn(flows=2), BackgroundTasks(), user=user) == 409

            inv.status = "finished"
            await db.commit()
            assert await status_of(routes.add_action, case_id, inv.id, add(tool="search_events", params={"query": "y"}),
                                   BackgroundTasks(), user=user) == 409
    _run(go())


# ─── Leases and adoption (spec Phase 1b) ─────────────────────────

def _new_run(user_id, case_id, **values):
    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation

    async def go():
        async with AsyncSessionLocal() as db:
            inv = CaseInvestigation(case_id=case_id, group_id="blue", started_by=user_id, steps=[], **values)
            db.add(inv)
            await db.commit()
            return inv.id
    return _run(go())


def _get_run(inv_id):
    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation

    async def go():
        async with AsyncSessionLocal() as db:
            return await db.get(CaseInvestigation, inv_id)
    return _run(go())


async def _until(predicate, timeout=20.0):
    """Poll an async predicate until it returns something truthy."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(0.2)
    raise AssertionError("condition not reached")


async def _crash(task):
    """What a dying process looks like to the run: cancelled mid-await, nothing finalized."""
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def test_leases_are_exclusive_until_they_expire(env, monkeypatch):
    from datetime import timedelta

    from app.services import investigator

    user_id, _, case_id = _seed(f"lease-{uuid.uuid4().hex[:8]}")
    queued = _new_run(user_id, case_id, status="queued")
    assert _run(investigator._claim(queued))
    monkeypatch.setattr(investigator, "REPLICA_ID", "replica-b")
    assert not _run(investigator._claim(queued))  # held by the first replica
    expired = _new_run(user_id, case_id, status="running", lease_owner="dead-replica",
                       lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=5))
    assert _run(investigator._claim(expired))
    # a run from before leases is adopted only once its old replica stopped updating it
    fresh_legacy = _new_run(user_id, case_id, status="running")
    stale_legacy = _new_run(user_id, case_id, status="running",
                            updated_at=datetime.now(timezone.utc) - investigator.STALE_AFTER - timedelta(minutes=1))
    assert not _run(investigator._claim(fresh_legacy))
    assert _run(investigator._claim(stale_legacy))
    finished = _new_run(user_id, case_id, status="finished")
    assert not _run(investigator._claim(finished))


def test_an_adopted_run_awaits_its_flow_instead_of_scheduling_it_again(env, monkeypatch):
    from datetime import timedelta

    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation, Flow, InvestigationAction
    from app.services import investigator

    host = f"resume-{uuid.uuid4().hex[:8]}"
    user_id, agent_id, case_id = _seed(host)
    inv_id = _new_run(user_id, case_id)
    st = {}

    def before(turn, results):
        if turn == 1:
            return ("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": host, "reason": "what runs"})
        raise AssertionError("the first replica dies before seeing the result")

    def after(turn, results, messages):
        if turn == 1:
            brief = messages[2].content
            assert "moved to another server" in brief and "#1 run_artifact" in brief and "→ completed" in brief
            st["ev"] = brief.split("evidence_id ", 1)[1].split(":", 1)[0]
            return json.dumps({"verdict": "true_positive", "confidence": 80, "executive_summary": "Miner.",
                               "claims": [{"id": "c1", "section": "analysis", "text": "kworkerd from /tmp",
                                           "evidence_ids": [st["ev"]]}]})
        raise AssertionError(f"unexpected turn {turn}")

    async def go():
        async def flows():
            async with AsyncSessionLocal() as db:
                return (await db.execute(select(Flow).where(Flow.agent_id == agent_id))).scalars().all()

        # replica A schedules the flow, then dies while waiting for the agent
        monkeypatch.setattr(investigator, "make_chat_model", lambda *a, **k: Scripted(before))
        run = asyncio.create_task(investigator.run_investigation(inv_id))
        await _until(flows)
        await _crash(run)
        async with AsyncSessionLocal() as db:
            [row] = (await db.execute(select(InvestigationAction).where(
                InvestigationAction.investigation_id == inv_id))).scalars().all()
            assert row.status == "running" and row.result_ref["flow_id"]  # linked when it was scheduled
            assert (await db.get(CaseInvestigation, inv_id)).status == "running"
            await db.execute(update(CaseInvestigation).where(CaseInvestigation.id == inv_id).values(
                lease_owner="dead-replica", lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
            await db.commit()

        # replica B adopts it; the agent answers now
        model = Scripted(after)
        monkeypatch.setattr(investigator, "make_chat_model", lambda *a, **k: model)
        stop = asyncio.Event()
        agent = asyncio.create_task(_fake_agent(stop))
        assert inv_id in await investigator.adopt_orphans()
        await asyncio.wait_for(investigator._owned[inv_id], 60)
        stop.set()
        await agent
        assert len(await flows()) == 1  # awaited, not scheduled again
    _run(go())

    inv = _get_run(inv_id)
    assert inv.status == "finished", inv.error
    assert inv.verdict == "true_positive" and inv.report_json["claims"][0]["verified"]
    assert inv.lease_owner == investigator.REPLICA_ID and inv.lease_expires_at <= datetime.now(timezone.utc)
    kinds = [s["kind"] for s in inv.steps]
    assert kinds.count("started") == 1 and "resumed" in kinds and "reconciled" in kinds
    [row] = _rows(InvestigationAction, inv_id)
    assert row.status == "completed" and row.result_ref["evidence_ids"] == [st["ev"]]


def test_a_pending_command_survives_adoption_and_runs_once(env, monkeypatch):
    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.models.models import Flow, InvestigationAction, InvestigationCommand
    from app.services import investigator

    _set_setting("ai_command_execution", "approval")
    _set_setting("ai_command_autoapprove", "")
    host = f"resume-{uuid.uuid4().hex[:8]}"
    user_id, agent_id, case_id = _seed(host)
    inv_id = _new_run(user_id, case_id)

    def before(turn, results):
        if turn == 1:
            return ("run_command", {"host": host, "command": "ss", "args": ["-tnp"], "reason": "sockets"})
        raise AssertionError("the first replica dies while the command waits for approval")

    def after(turn, results, messages):
        if turn == 1:
            assert "#1 run_command" in messages[2].content and "→ completed" in messages[2].content
            return "## Summary\nSockets checked after the move.\nVERDICT: inconclusive"
        raise AssertionError(f"unexpected turn {turn}")

    async def go():
        async def pending():
            async with AsyncSessionLocal() as db:
                return (await db.execute(select(InvestigationCommand).where(
                    InvestigationCommand.investigation_id == inv_id,
                    InvestigationCommand.status == "pending"))).scalars().first()

        monkeypatch.setattr(investigator, "make_chat_model", lambda *a, **k: Scripted(before))
        run = asyncio.create_task(investigator.run_investigation(inv_id))
        cmd = await _until(pending)
        await _crash(run)
        assert (await pending()) is not None  # not expired by the dying replica

        monkeypatch.setattr(investigator, "make_chat_model", lambda *a, **k: Scripted(after))
        stop = asyncio.Event()
        agent = asyncio.create_task(_fake_agent(stop))
        resumed = asyncio.create_task(investigator.run_investigation(inv_id))
        await asyncio.sleep(1.0)  # the adopted run is waiting on the same command
        async with AsyncSessionLocal() as db:
            await db.execute(update(InvestigationCommand).where(InvestigationCommand.id == cmd.id)
                             .values(status="approved", decided_by=user_id))
            await db.commit()
        await asyncio.wait_for(resumed, 60)
        stop.set()
        await agent
        async with AsyncSessionLocal() as db:
            flows = (await db.execute(select(Flow).where(Flow.agent_id == agent_id))).scalars().all()
            cmds = (await db.execute(select(InvestigationCommand).where(
                InvestigationCommand.investigation_id == inv_id))).scalars().all()
            [action] = (await db.execute(select(InvestigationAction).where(
                InvestigationAction.investigation_id == inv_id))).scalars().all()
        assert len(cmds) == 1 and cmds[0].flow_id is not None
        assert [f.id for f in flows] == [cmds[0].flow_id]  # one command, one flow
        assert action.status == "completed" and action.result_ref["flow_id"] == str(cmds[0].flow_id)
    try:
        _run(go())
    finally:
        _set_setting("ai_command_execution", "off")
    assert _get_run(inv_id).status == "finished"


def test_a_lost_lease_stops_this_copy_without_finishing_the_run(env, monkeypatch):
    from sqlalchemy import update

    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseInvestigation
    from app.services import investigator

    monkeypatch.setattr(investigator, "LEASE_RENEW_SECONDS", 0.3)
    user_id, _, case_id = _seed(f"lease-{uuid.uuid4().hex[:8]}")
    inv_id = _new_run(user_id, case_id, status="queued")

    async def slow_hosts(ctx, hostname_contains=""):
        await asyncio.sleep(0.2)
        return {"hosts": []}
    monkeypatch.setattr(investigator, "list_hosts", slow_hosts)
    monkeypatch.setattr(investigator, "make_chat_model",
                        lambda *a, **k: Scripted(lambda turn, results: ("list_hosts", {"hostname_contains": str(turn)})))

    async def go():
        investigator.spawn(inv_id)
        task = investigator._owned[inv_id]
        await asyncio.sleep(1.0)
        async with AsyncSessionLocal() as db:  # another replica took it over
            await db.execute(update(CaseInvestigation).where(CaseInvestigation.id == inv_id)
                             .values(lease_owner="replica-b"))
            await db.commit()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)
    _run(go())
    inv = _get_run(inv_id)
    assert inv.status == "running" and inv.finished_at is None  # left for the replica that holds it
    assert inv.lease_owner == "replica-b" and inv.rounds_used >= 1


def test_text_tool_calls_run_and_garbled_output_never_reaches_the_case(env, monkeypatch):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.models import CaseNote

    user_id, _, case_id = _seed()
    garbled = "Searching for the IP 80.94.92.27 and the destination is" + "<unk>" * 200

    def script(turn, results):
        if turn == 1:  # a model that writes its tool call as Qwen-style text
            return ("The host is offline; list the hosts first.\n<tool_call>\n<function=list_hosts>\n"
                    "<parameter=hostname_contains>\nweb\n</parameter>\n</function>\n</tool_call>")
        if turn == 2:
            assert results[-1]["hosts"][0]["hostname"] == "web01"  # the text call really ran
            return garbled
        if turn == 3:
            return garbled  # the retry degenerates too
        if turn == 4:
            return "## Summary\nBrute force from 80.94.92.27; host offline, nothing collected.\nVERDICT: inconclusive"
        raise AssertionError(f"unexpected turn {turn}")

    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished" and inv.verdict == "inconclusive"
    assert "<unk>" not in inv.report
    kinds = [s["kind"] for s in inv.steps]
    assert kinds.count("warning") == 2 and "tool" in kinds
    assert not any("<unk>" in json.dumps(s) for s in inv.steps)
    assert "Stop investigating" in model.seen[-1][-1].content

    async def check():
        async with AsyncSessionLocal() as db:
            notes = (await db.execute(select(CaseNote).where(CaseNote.case_id == case_id))).scalars().all()
            assert len(notes) == 1 and "<unk>" not in notes[0].content
    _run(check())


def _set_setting(key, value):
    from app.core.database import AsyncSessionLocal
    from app.models.models import PlatformSetting

    async def go():
        async with AsyncSessionLocal() as db:
            row = await db.get(PlatformSetting, key)
            if row is None:
                db.add(PlatformSetting(key=key, value=value))
            else:
                row.value = value
            await db.commit()
    _run(go())


def test_commands_wait_for_an_analyst(env, monkeypatch):
    """approve → runs as an exec flow; reject → never scheduled; allowlisted → runs without asking."""
    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.models.models import Flow, InvestigationAction, InvestigationCommand, InvestigationEvidence

    _set_setting("ai_command_execution", "approval")
    _set_setting("ai_command_autoapprove", "hostname, bash")
    user_id, _, case_id = _seed()
    seen_pending = []

    async def analyst(stop):
        # approves ss, rejects everything else that waits
        while not stop.is_set():
            async with AsyncSessionLocal() as db:
                for cmd in (await db.execute(select(InvestigationCommand).where(
                        InvestigationCommand.status == "pending"))).scalars().all():
                    seen_pending.append(cmd.command)
                    ok = cmd.command == "ss"
                    await db.execute(update(InvestigationCommand).where(InvestigationCommand.id == cmd.id).values(
                        status="approved" if ok else "rejected", decided_by=user_id,
                        decision_note=None if ok else "too broad"))
                await db.commit()
            await asyncio.sleep(0.3)

    def script(turn, results):
        if turn == 1:
            return ("run_command", {"host": "web01", "command": "ss", "args": ["-tnp"],
                                    "reason": "who talks to 203.0.113.9"})
        if turn == 2:
            assert results[-1]["status"] == "finished", results[-1]
            assert results[-1]["stdout"] == "ran: ss -tnp" and "exit code 0" in results[-1]["exit"]
            return ("run_command", {"host": "web01", "command": "bash", "args": ["-c", "id"], "reason": "who am i"})
        if turn == 3:
            assert "rejected (too broad)" in results[-1]["error"]
            return ("run_command", {"host": "web01", "command": "/usr/bin/hostname", "args": [], "reason": "name"})
        if turn == 4:
            assert results[-1]["stdout"] == "ran: /usr/bin/hostname"
            return "## Summary\nChecked sockets.\nVERDICT: inconclusive"
        raise AssertionError(f"unexpected turn {turn}")

    stop = asyncio.Event()
    approver = _LOOP.create_task(analyst(stop))
    try:
        inv, model = _investigate(script, monkeypatch, user_id, case_id)
    finally:
        stop.set()
        _run(approver)
        _set_setting("ai_command_execution", "off")
    assert inv.status == "finished", inv.error
    assert seen_pending == ["ss", "bash"]  # hostname was auto-approved; bash never is
    assert "run_command" in model.tool_names
    assert "Commands: run_command" in model.seen[0][0].content
    assert [s["status"] for s in inv.steps if s["kind"] == "command_decision"] == ["approved", "rejected"]

    async def check():
        async with AsyncSessionLocal() as db:
            cmds = (await db.execute(select(InvestigationCommand).where(
                InvestigationCommand.investigation_id == inv.id).order_by(InvestigationCommand.created_at)
            )).scalars().all()
            assert [(c.command, c.status, c.auto_approved, c.flow_id is not None) for c in cmds] == [
                ("ss", "approved", False, True), ("bash", "rejected", False, False),
                ("/usr/bin/hostname", "approved", True, True)]
            flows = (await db.execute(select(Flow).where(Flow.id.in_([c.flow_id for c in cmds if c.flow_id]))
                                      )).scalars().all()
            assert {f.artifact for f in flows} == {"AI.Command"}
            assert all(f.request["sources"][0]["plugin"] == "exec" for f in flows)
            assert flows and all(f.created_by == user_id for f in flows)
            # each command is a tier-2 action in the ledger, linked to its command row
            actions = (await db.execute(select(InvestigationAction).where(
                InvestigationAction.investigation_id == inv.id).order_by(InvestigationAction.ordinal))).scalars().all()
            assert [(a.params["command"], a.status, a.risk_tier, a.decision_note) for a in actions] == [
                ("ss", "completed", 2, None), ("bash", "skipped", 2, "too broad"), ("/usr/bin/hostname", "completed", 2, None)]
            assert [a.result_ref["command_id"] for a in actions] == [str(c.id) for c in cmds]
            evidence = (await db.execute(select(InvestigationEvidence).where(
                InvestigationEvidence.investigation_id == inv.id,
                InvestigationEvidence.evidence_type == "command_result"))).scalars().all()
            assert len(evidence) == 2 and all(e.sensitivity == "sensitive" for e in evidence)
    _run(check())


def test_commands_are_off_by_default(env, monkeypatch):
    _set_setting("ai_command_execution", "off")
    user_id, _, case_id = _seed()

    def script(turn, results):
        if turn == 1:
            return ("run_command", {"host": "web01", "command": "id", "args": [], "reason": "x"})
        assert "unknown tool" in results[-1]["error"]
        return "## Summary\nNothing.\nVERDICT: inconclusive"

    inv, model = _investigate(script, monkeypatch, user_id, case_id)
    assert inv.status == "finished"
    assert "run_command" not in model.tool_names
    assert "cannot run commands" in model.seen[0][0].content
