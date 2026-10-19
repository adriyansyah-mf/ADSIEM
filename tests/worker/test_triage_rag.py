# tests/worker/test_triage_rag.py
"""RAG on the live triage path: what the retrieve node finds (similar closed
cases, SOP passages, analyst corrections) must reach the L1 prompt."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.graph import triage_graph  # noqa: E402
from worker.llm_client import rag_sections  # noqa: E402

CASE = {"title": "SSH brute force then login on web01", "description": "Closed: attacker IP blocked, key rotated",
        "status": "closed", "similarity": 0.83}
SOP = ["[ir-playbook.pdf] Successful login after brute force: isolate the host, reset the account, rotate keys."]
FEEDBACK = {"rating": "incorrect", "ai_verdict": "monitor", "correct_verdict": "create_case",
            "note": "logins from this ASN are never benign", "similarity": 0.77}


class _FakeLLM:
    prompts: list[str] = []

    def __init__(self, **kwargs):
        pass

    async def ainvoke(self, messages):
        _FakeLLM.prompts.append(messages[-1].content)

        class _Reply:
            content = json.dumps({"verdict": "monitor", "confidence": 0.5, "triage_notes": "x",
                                  "mitre_techniques": [], "immediate_actions": [], "search_queries": []})
        return _Reply()


def _deps(cases, sop, feedback):
    class _Enrichment:
        provider_bullets, overall_risk, triage_hints, iocs = [], 0.0, [], []

    async def noop(*a, **k):
        return None

    async def enrich(text_blob, title):
        return _Enrichment()

    async def get_setting(key, default=""):
        return default

    def returns(value):
        async def f(*a, **k):
            return value
        return f

    return {
        "enrich": enrich, "escalate_severity": lambda base, risk: base, "suggest_mitre": lambda text: [],
        "retrieve_similar_cases": returns(cases), "retrieve_sop_context": returns(sop),
        "retrieve_feedback_context": returns(feedback),
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop, "write_alert_note": noop,
        "tag_alert_with_mitre": noop, "run_soar_playbooks": noop, "update_alert_status": noop, "run_searches": noop,
        "find_existing_open_case": noop, "add_note_to_existing_case": noop, "create_case_from_verdict": noop,
        "analyze_campaign": noop, "check_fleet_spread": noop, "dispatch_case_webhooks": noop,
    }


def _state():
    return {"alert_id": "22222222-2222-2222-2222-222222222222", "title": "Successful Login After Brute Force",
            "severity": "critical", "source_ip": "203.0.113.9", "hostname": "web01",
            "decoded_fields": {"event.action": "login_success"}, "group_id": "default"}


async def _prompt(monkeypatch, cases, sop, feedback, thread):
    _FakeLLM.prompts = []
    monkeypatch.setattr(triage_graph, "NineRouterChatModel", _FakeLLM)
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=_deps(cases, sop, feedback))
    await graph.ainvoke(_state(), {"configurable": {"thread_id": thread}})
    return _FakeLLM.prompts[0]


async def test_retrieved_context_reaches_the_triage_prompt(monkeypatch):
    prompt = await _prompt(monkeypatch, [CASE], SOP, [FEEDBACK], "rag-1")
    assert "LEARNINGS FROM PREVIOUS CASES" in prompt and "attacker IP blocked, key rotated" in prompt
    assert "COMPANY SOP" in prompt and "isolate the host, reset the account" in prompt
    assert "INCORRECT" in prompt and "should have been 'create_case'" in prompt
    assert "never benign" in prompt


async def test_nothing_retrieved_adds_nothing(monkeypatch):
    prompt = await _prompt(monkeypatch, [], [], [], "rag-2")
    assert "LEARNINGS FROM PREVIOUS CASES" not in prompt and "COMPANY SOP" not in prompt
    assert rag_sections(None, None, None) == ""
