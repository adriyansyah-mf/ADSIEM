# tests/worker/test_ueba_ai_triage.py
"""UEBA alerts on the AI triage path: entity context reaches the prompt and the
verdict is handed back. The LLM is faked, so this runs without a 9router."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.graph import triage_graph


class _FakeLLM:
    prompts: list[str] = []

    def __init__(self, **kwargs):
        pass

    async def ainvoke(self, messages):
        _FakeLLM.prompts.append(messages[-1].content)

        class _Reply:
            content = json.dumps({
                "verdict": "create_case", "confidence": 0.9, "triage_notes": "Password spraying from one IP.",
                "mitre_techniques": ["T1110.003"], "immediate_actions": ["Block 203.0.113.9"],
                "false_positive_reason": None, "threat_type": "brute_force", "search_queries": [],
            })
        return _Reply()


def _deps(calls):
    class _Enrichment:
        provider_bullets, overall_risk, triage_hints, iocs = [], 0.0, [], []

    async def noop(*a, **k):
        return None

    async def empty(*a, **k):
        return []

    async def no_case(*a, **k):
        return None, []

    async def enrich(text_blob, title):
        return _Enrichment()

    async def get_setting(key, default=""):
        return default

    async def create_case(**kwargs):
        return "case-123"

    async def ueba_context(fields, group_id):
        calls.append(("ueba_context", fields["ueba_entity_value"]))
        return "Entity: ip 203.0.113.9\nRecent anomalies: distinct usernames tried 47 vs typical 1"

    async def record_outcome(**kwargs):
        calls.append(("record_outcome", kwargs))

    return {
        "enrich": enrich, "escalate_severity": lambda base, risk: base,
        "suggest_mitre": lambda text: [], "retrieve_similar_cases": empty,
        "retrieve_sop_context": empty, "retrieve_feedback_context": empty,
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop,
        "write_alert_note": noop, "tag_alert_with_mitre": noop, "run_soar_playbooks": noop,
        "update_alert_status": noop, "run_searches": noop, "find_campaign_case": no_case,
        "join_campaign_case": noop, "create_case_from_verdict": create_case,
        "analyze_campaign": noop, "check_fleet_spread": noop, "dispatch_case_webhooks": noop,
        "ueba_context": ueba_context, "record_outcome": record_outcome,
    }


def _state(fields):
    return {"alert_id": "11111111-1111-1111-1111-111111111111", "title": "[UEBA] Ip anomaly: 203.0.113.9",
            "severity": "high", "source_ip": "203.0.113.9", "hostname": None,
            "decoded_fields": fields, "group_id": "default"}


async def test_ai_grouping_links_existing_case_without_creating_or_merging():
    from worker.case_correlation import Decision
    calls = []
    deps = _deps(calls)
    case_id = "22222222-2222-2222-2222-222222222222"

    async def choose(incoming):
        return Decision(action="join", case_id=case_id, confidence=0.95, reason="Shared evidence")

    async def record(incoming, decision):
        calls.append(("link", str(decision.case_id), incoming.alert_id))
        return True

    async def join(**kwargs):
        calls.append(("join", kwargs["case_id"], kwargs["merge"]))
        return {}

    deps.update(choose_case=choose, record_link=record, join_campaign_case=join)
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    final = await graph.ainvoke(_state({"user.name": "admin"}))
    assert final["case_id"] == case_id
    assert ("join", case_id, []) in calls
    assert len([c for c in calls if c[0] == "link"]) == 1


async def test_ambiguous_grouping_records_suggestion_and_creates_separate_case():
    from worker.case_correlation import Decision
    calls = []
    deps = _deps(calls)
    candidate_id = "22222222-2222-2222-2222-222222222222"
    new_id = "33333333-3333-3333-3333-333333333333"

    async def choose(incoming):
        return Decision(action="suggest", case_id=candidate_id, confidence=0.6, reason="Uncertain evidence")

    async def record(incoming, decision):
        calls.append(("link", str(decision.case_id), decision.action))
        return True

    async def create(**kwargs):
        return new_id

    deps.update(choose_case=choose, record_link=record, create_case_from_verdict=create)
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    final = await graph.ainvoke(_state({"user.name": "admin"}))
    assert final["case_id"] == new_id
    assert ("link", candidate_id, "suggest") in calls
    assert ("link", new_id, "join") in calls


@pytest.fixture(autouse=True)
def fake_llm(monkeypatch):
    _FakeLLM.prompts = []
    monkeypatch.setattr(triage_graph, "NineRouterChatModel", _FakeLLM)


async def test_ueba_alert_gets_entity_context_and_records_the_verdict():
    calls = []
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=_deps(calls))
    fields = {"ueba_entity_type": "ip", "ueba_entity_value": "203.0.113.9",
              "ueba_reasons": ["distinct usernames tried 47 vs typical 1"]}
    final = await graph.ainvoke(_state(fields), {"configurable": {"thread_id": "ueba-ai-1"}})

    assert ("ueba_context", "203.0.113.9") in calls
    assert "UEBA BEHAVIOUR CONTEXT" in _FakeLLM.prompts[0]
    assert "distinct usernames tried 47 vs typical 1" in _FakeLLM.prompts[0]
    recorded = [c[1] for c in calls if c[0] == "record_outcome"]
    assert recorded == [{"alert_id": "11111111-1111-1111-1111-111111111111", "verdict": "create_case",
                         "notes": "Password spraying from one IP.", "case_id": "case-123"}]
    assert final["case_id"] == "case-123"


async def test_non_ueba_alert_skips_ueba_context_but_still_records():
    calls = []
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=_deps(calls))
    await graph.ainvoke(_state({"event.action": "login_failed"}), {"configurable": {"thread_id": "ueba-ai-2"}})
    assert not any(c[0] == "ueba_context" for c in calls)
    assert "UEBA BEHAVIOUR CONTEXT" not in _FakeLLM.prompts[0]
    assert any(c[0] == "record_outcome" for c in calls)  # a no-op for non-UEBA alerts in ai_analyst


async def test_graph_without_ueba_hooks_still_runs():
    calls = []
    deps = _deps(calls)
    del deps["ueba_context"], deps["record_outcome"]
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    final = await graph.ainvoke(_state({"ueba_entity_type": "ip", "ueba_entity_value": "1.2.3.4"}),
                                {"configurable": {"thread_id": "ueba-ai-3"}})
    assert final["verdict"] == "create_case"
