# tests/worker/test_triage_graph_live.py
"""Live tests for the LangGraph triage pipeline against a real 9router.

Calls the actual model — nothing is mocked. Skipped unless
NINEROUTER_TEST_BASE_URL / NINEROUTER_TEST_API_KEY are set, so CI stays
hermetic.

Run locally:
    NINEROUTER_TEST_BASE_URL=... \\
    NINEROUTER_TEST_API_KEY=... \\
    NINEROUTER_TEST_MODEL=... \\
    pytest tests/worker/test_triage_graph_live.py -v
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("NINEROUTER_TEST_BASE_URL") and os.environ.get("NINEROUTER_TEST_API_KEY")),
    reason="live 9router not configured (set NINEROUTER_TEST_BASE_URL + NINEROUTER_TEST_API_KEY)",
)

BASE_URL = os.environ.get("NINEROUTER_TEST_BASE_URL", "")
API_KEY = os.environ.get("NINEROUTER_TEST_API_KEY", "")
MODEL = os.environ.get("NINEROUTER_TEST_MODEL", "combo")


def _recording_deps(calls, verdict_override=None):
    """Real control flow with side effects recorded instead of persisted."""

    class _Enrichment:
        provider_bullets = []
        overall_risk = 0.0
        triage_hints = []
        iocs = []

    async def enrich(text_blob, alert_title):
        calls.append("enrich")
        return _Enrichment()

    def escalate(base, risk):
        return base

    def suggest(text):
        return ["T1110: Brute Force"]

    async def no_cases(q, gid):
        return []

    async def no_sop(q, gid):
        return []

    async def no_feedback(q, gid):
        return []

    async def enqueue(ip, gid):
        calls.append(("enqueue_hunt", ip))

    async def get_setting(key, default=""):
        calls.append(("get_setting", key))
        return default

    async def set_verdict(aid, v):
        calls.append(("set_alert_verdict", v))

    async def write_note(aid, content):
        calls.append(("write_alert_note", aid))

    async def tag_mitre(aid, techniques):
        calls.append("tag_alert_with_mitre")

    async def run_soar(**kwargs):
        calls.append(("run_soar", kwargs.get("ai_verdict")))

    async def update_status(aid, status):
        calls.append(("update_alert_status", status))

    async def run_searches(aid, cid, queries):
        calls.append("run_searches")

    async def find_case(ip, host, gid):
        return None

    async def add_note(cid, aid, title, notes, sev):
        calls.append("add_note_to_existing_case")

    async def create_case(**kwargs):
        calls.append(("create_case", kwargs.get("verdict")))
        return "case-0001"

    async def campaign(**kwargs):
        calls.append("analyze_campaign")

    async def fleet(cid, title, gid, hostname):
        calls.append("check_fleet_spread")

    async def webhooks(**kwargs):
        calls.append("dispatch_case_webhooks")

    return {
        "enrich": enrich,
        "escalate_severity": escalate,
        "suggest_mitre": suggest,
        "retrieve_similar_cases": no_cases,
        "retrieve_sop_context": no_sop,
        "retrieve_feedback_context": no_feedback,
        "enqueue_hunt": enqueue,
        "get_setting": get_setting,
        "set_alert_verdict": set_verdict,
        "write_alert_note": write_note,
        "tag_alert_with_mitre": tag_mitre,
        "run_soar_playbooks": run_soar,
        "update_alert_status": update_status,
        "run_searches": run_searches,
        "find_existing_open_case": find_case,
        "add_note_to_existing_case": add_note,
        "create_case_from_verdict": create_case,
        "analyze_campaign": campaign,
        "check_fleet_spread": fleet,
        "dispatch_case_webhooks": webhooks,
    }


def _state(severity="high", title="SSH Brute Force"):
    return {
        "alert_id": "11111111-1111-1111-1111-111111111111",
        "title": title,
        "severity": severity,
        "source_ip": "203.0.113.5",
        "hostname": "web-01",
        "decoded_fields": {"event.action": "login_failed", "user.name": "root"},
        "group_id": "default",
        "similar_cases": [],
        "sop_context": [],
        "feedback_context": [],
    }


def _parse(text):
    import json

    content = (text or "").strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    return json.loads(content)


async def test_triage_graph_runs_full_pipeline():
    from worker.graph.triage_graph import build_triage_graph

    calls = []
    graph = build_triage_graph(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL,
        deps=_recording_deps(calls),
    )
    final = await graph.ainvoke(_state(), {"configurable": {"thread_id": "live-triage-1"}})

    verdict = final.get("verdict")
    assert verdict in ("escalate", "create_case", "monitor", "false_positive"), verdict
    assert final.get("triage_notes"), "no triage notes produced"
    assert "enrich" in calls
    assert any(c[0] == "set_alert_verdict" for c in calls if isinstance(c, tuple))
    assert any(c[0] == "write_alert_note" for c in calls if isinstance(c, tuple))
    assert any(c[0] == "update_alert_status" for c in calls if isinstance(c, tuple))


async def test_high_severity_does_not_end_as_false_positive():
    """The pipeline must not classify a high/critical alert as benign without
    very strong justification, per its own triage rules."""
    from worker.graph.triage_graph import build_triage_graph

    calls = []
    graph = build_triage_graph(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL,
        deps=_recording_deps(calls),
    )
    final = await graph.ainvoke(
        _state(severity="critical", title="Kernel Module Load From Suspicious Path"),
        {"configurable": {"thread_id": "live-triage-2"}},
    )
    assert final.get("verdict") != "false_positive", final.get("verdict")


async def test_low_severity_benign_alert_stays_quiet():
    from worker.graph.triage_graph import build_triage_graph

    calls = []
    graph = build_triage_graph(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL,
        deps=_recording_deps(calls),
    )
    final = await graph.ainvoke(
        _state(severity="info", title="Successful sudo to ROOT executed"),
        {"configurable": {"thread_id": "live-triage-3"}},
    )
    assert final.get("verdict") in ("monitor", "false_positive", "create_case"), final.get("verdict")


async def test_triage_produces_parseable_structured_output():
    from worker.graph.chat_model import NineRouterChatModel
    from worker.graph.triage_graph import _L1_SYSTEM_PROMPT

    from langchain_core.messages import HumanMessage, SystemMessage

    llm = NineRouterChatModel(base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=1200)
    reply = await llm.ainvoke([
        SystemMessage(content=_L1_SYSTEM_PROMPT),
        HumanMessage(content=(
            "ALERT TO TRIAGE:\nTitle: SSH Brute Force\nSeverity: high\n"
            "Source IP: 203.0.113.5\nHostname: web-01\nFields: {}"
        )),
    ])
    parsed = _parse(reply.content)
    assert parsed["verdict"] in ("escalate", "create_case", "monitor", "false_positive")
    assert 0.0 <= float(parsed.get("confidence", 0.0)) <= 1.0
