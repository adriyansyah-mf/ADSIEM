# tests/server-api/test_investigation_ledger.py
"""The investigation ledger's policy, without a database: risk tiers, repeat
refusal, evidence extraction, hypothesis rules and report citation checks."""
import json
import uuid
from types import SimpleNamespace

import pytest

from app.models.models import InvestigationAction, InvestigationHypothesis
from app.services import investigation_ledger as ledger

INV = uuid.uuid4()


def _ev(kind="flow_row", title="pslist on web01"):
    return SimpleNamespace(evidence_type=kind, title=title, entities={})


def test_tiers_come_from_what_the_tool_does():
    assert ledger.tool_tier("search_events") == 0
    assert ledger.tool_tier("create_artifact") == 0  # authoring; running it is what touches a host
    assert ledger.tool_tier("run_artifact") == 1
    assert ledger.tool_tier("run_command") == 2
    assert ledger.tool_tier("something_new") == 2  # unclassified: a person decides


def test_artifact_tier_checks_content_author_and_host_budget():
    base = dict(artifact="Linux.Sys.Pslist", plugins={"pslist"}, created_by_investigation=None, promoted=True,
                investigation_id=INV, host_auto_runs=0)
    assert ledger.artifact_tier(**base) == ledger.Tier(1)
    # stored content with a non-read-only plugin is tier 2, whoever wrote it
    assert ledger.artifact_tier(**{**base, "plugins": {"pslist", "exec"}}).tier == 2
    # another run's AI artifact waits for a person until promoted; this run's own does not
    foreign = {**base, "artifact": "AI.Linux.X", "promoted": False, "created_by_investigation": uuid.uuid4()}
    assert "another AI investigation" in ledger.artifact_tier(**foreign).approval_reason
    assert ledger.artifact_tier(**{**foreign, "created_by_investigation": INV}).approval_reason is None
    assert ledger.artifact_tier(**{**foreign, "promoted": True}).approval_reason is None
    # the per-host automatic budget
    over = ledger.artifact_tier(**{**base, "host_auto_runs": ledger.HOST_AUTO_FLOWS})
    assert over.tier == 1 and "automatic collections" in over.approval_reason


def test_idempotency_key_ignores_reason_case_order_and_empty_values():
    a = ledger.idempotency_key("run_artifact", "WEB01", {"artifact": "Linux.Sys.Pslist", "params": {"a": 1, "b": ""}})
    b = ledger.idempotency_key("run_artifact", "web01 ", {"params": {"a": 1}, "artifact": " Linux.Sys.Pslist"})
    assert a == b
    assert a != ledger.idempotency_key("run_artifact", "web02", {"artifact": "Linux.Sys.Pslist", "params": {"a": 1}})
    target, params, reason = ledger.split_args({"host": "web01", "artifact": "X", "reason": "why"})
    assert (target, params, reason) == ("web01", {"artifact": "X"}, "why")


def _row(**kw):
    defaults = dict(ordinal=3, status="completed", risk_tier=1, attempts=1, result_ref={}, error=None,
                    decision_note=None)
    return InvestigationAction(**{**defaults, **kw})


def test_endpoint_work_never_repeats_but_queries_may():
    assert "already ran as action #3" in ledger.repeat_refusal(_row(result_ref={"evidence_ids": ["e1"]}))
    assert ledger.repeat_refusal(_row(risk_tier=0)) is None  # logs keep arriving: search again
    assert "skipped or rejected" in ledger.repeat_refusal(_row(status="skipped", risk_tier=0, decision_note="no"))
    assert ledger.repeat_refusal(_row(status="failed", attempts=1)) is None  # one retry
    assert "failed 2 times" in ledger.repeat_refusal(_row(status="failed", attempts=2, error="offline"))


def test_flow_sources_become_evidence_and_get_ids():
    result = {"flow_id": "f1", "artifact": "Linux.Sys.Pslist", "status": "finished", "sources": [
        {"source": "Procs", "total_rows": 1, "rows": [{"Pid": 1, "Exe": "/tmp/x"}]},
        {"source": "Empty", "total_rows": 0, "rows": []},
    ]}
    specs = ledger.evidence_specs("run_artifact", {"artifact": "Linux.Sys.Pslist", "host": "web01"}, result)
    assert [s.source_id for s in specs] == ["f1:Procs", "f1:Empty"]  # nothing found is evidence too
    assert specs[0].entities == {"hosts": ["web01"]} and "/tmp/x" in specs[0].summary
    ids = [uuid.uuid4(), uuid.uuid4()]
    ledger.attach_ids(result, specs, ids)
    assert result["sources"][1]["evidence_id"] == str(ids[1])
    # errors and listings observe nothing; knowledge is guidance, not proof
    assert ledger.evidence_specs("run_artifact", {}, {"error": "offline"}) == []
    assert ledger.evidence_specs("list_hosts", {}, {"hosts": []}) == []
    k = ledger.evidence_specs("search_knowledge", {"query": "scanner"}, {"notes": [{"id": "n1", "title": "Nessus"}]})
    assert k[0].evidence_type == ledger.KNOWLEDGE
    assert k[0].entities == {"knowledge_ids": ["n1"], "titles": {"n1": "Nessus"}, "headings": {}}


def _hyp(source="planner"):
    return InvestigationHypothesis(statement="Miner from /tmp", state="open", confidence=50, source=source,
                                   supporting_evidence_ids=[], contradicting_evidence_ids=[], open_questions=[],
                                   history=[])


def test_hypotheses_close_only_with_evidence_from_this_run():
    index = {"e1": _ev(), "k1": _ev(ledger.KNOWLEDGE)}
    h = _hyp()
    with pytest.raises(ledger.HypothesisError, match="needs supporting evidence"):
        ledger.apply_hypothesis_update(h, actor="ai", index=index, state="supported")
    with pytest.raises(ledger.HypothesisError, match="knowledge guidance"):
        ledger.apply_hypothesis_update(h, actor="ai", index=index, supporting=["k1"])
    with pytest.raises(ledger.HypothesisError, match="not from this investigation"):
        ledger.apply_hypothesis_update(h, actor="ai", index=index, supporting=["zz"])
    ledger.apply_hypothesis_update(h, actor="ai", index=index, state="supported", supporting=["e1"], confidence=140)
    assert (h.state, h.confidence, h.supporting_evidence_ids) == ("supported", 100, ["e1"])
    assert h.history[-1]["state"] == "supported"


def test_the_ai_only_proposes_closing_an_analysts_hypothesis():
    h = _hyp(source="analyst")
    entry = ledger.apply_hypothesis_update(h, actor="ai", index={"e1": _ev()}, state="supported", supporting=["e1"])
    assert h.state == "open" and entry["proposed_state"] == "supported"
    ledger.apply_hypothesis_update(h, actor="ana", index={"e1": _ev()}, state="supported")
    assert h.state == "supported"


def _report(**kw):
    return {"verdict": "true_positive", "confidence": 80, "executive_summary": "A miner ran.",
            "claims": [{"id": "c1", "section": "analysis", "text": "kworkerd ran from /tmp", "evidence_ids": ["e1"]}],
            "gaps": [], "recommended_actions": ["Isolate web01"], **kw}


def test_cited_report_validates_and_renders_with_footnotes():
    index = {"e1": _ev(), "k1": _ev(ledger.KNOWLEDGE, "Nessus note")}
    report, problems = ledger.validate_report(_report(), index, set())
    assert problems == [] and report["claims"][0]["verified"]
    md = ledger.render_markdown(ledger.finalize_report(report), index)
    assert "kworkerd ran from /tmp [E1]" in md and "**E1** pslist on web01" in md
    assert md.rstrip().endswith("VERDICT: true_positive") and "Unverified" not in md


def test_claims_without_own_evidence_are_flagged_and_the_verdict_downgraded():
    index = {"e1": _ev(), "k1": _ev(ledger.KNOWLEDGE)}
    raw = _report(claims=[
        {"id": "c1", "section": "analysis", "text": "from a note", "evidence_ids": ["k1"]},
        {"id": "c2", "section": "timeline", "text": "invented", "evidence_ids": ["nope"]},
        {"id": "c3", "section": "recommendation", "text": "per our SOP", "evidence_ids": ["k1"]},
    ], knowledge_citations=[{"entry_id": "unseen"}])
    report, problems = ledger.validate_report(raw, index, set())
    text = "\n".join(problems)
    assert "knowledge guidance, which cannot prove a claim in analysis" in text
    assert "nope is not evidence from this investigation" in text
    assert "knowledge citation unseen was not retrieved" in text
    assert [c["verified"] for c in report["claims"]] == [False, False, True]  # knowledge may back a recommendation
    final = ledger.finalize_report(report)
    assert final["verdict"] == "inconclusive" and final["verdict_downgraded_from"] == "true_positive"
    md = ledger.render_markdown(final, index)
    assert "## Unverified statements" in md and "⚠ invented" in md


def test_report_parsing_tolerates_fences_and_rejects_prose():
    obj = _report()
    assert ledger.parse_report("```json\n" + json.dumps(obj) + "\n```") == obj
    assert ledger.parse_report("Here it is: " + json.dumps(obj)) == obj
    assert ledger.parse_report("## Summary\nNo JSON here.\nVERDICT: inconclusive") is None
    bad, problems = ledger.validate_report({"verdict": "maybe", "claims": "x"}, {}, set())
    assert bad["verdict"] == "inconclusive" and any("claims must be a list" in p for p in problems)
