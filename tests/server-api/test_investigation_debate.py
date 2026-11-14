"""The review panel (services/investigation_debate.py): reviewers with
different stances test the lead's draft, answer each other, and the lead is
briefed on where they ended up."""
import asyncio
import json

import pytest

from app.services import investigation_debate as debate

# A loop of its own: asyncio.run() would leave the thread without a current
# event loop, and later test modules that call get_event_loop() would fail.
_LOOP = asyncio.new_event_loop()

DRAFT = '{"verdict": "true_positive", "summary": "webshell p.php ran recon as www-data"}'
KNOWN = {"ev-1", "ev-2"}


class Reviewer:
    """ainvoke like a chat model; the reply depends on the reviewer (system prompt) and the round."""

    def __init__(self, answer, calls, gate=None):
        self.answer, self.calls, self.gate = answer, calls, gate

    async def ainvoke(self, messages):
        from langchain_core.messages import AIMessage
        system, ask = messages[0].content, messages[1].content
        name = system.split("You are the ", 1)[1].split(" on a review panel", 1)[0]
        round_no = int(ask.split("Round ", 1)[1].split(" ", 1)[0])
        self.calls.append((name, round_no, ask))
        if self.gate is not None:
            self.gate["now"] += 1
            self.gate["most"] = max(self.gate["most"], self.gate["now"])
            await asyncio.sleep(0.01)
            self.gate["now"] -= 1
        out = self.answer(name, round_no, ask)
        if isinstance(out, Exception):
            raise out
        return AIMessage(content=out if isinstance(out, str) else json.dumps(out))


def position(verdict, agrees, summary="", challenges=(), missing=(), confidence=70):
    return {"verdict": verdict, "confidence": confidence, "agrees_with_draft": agrees, "summary": summary,
            "challenges": list(challenges), "missing_evidence": list(missing), "responses": []}


def run(answer, agents=3, rounds=2, gate=None, concurrency=3):
    calls, seen = [], []

    async def on_round(n, positions):
        seen.append((n, [p["name"] for p in positions]))
    result = _LOOP.run_until_complete(debate.run(lambda: Reviewer(answer, calls, gate), case_brief="case 1",
                                    draft=DRAFT, ledger_digest="- evidence_id ev-1: shell", known_ids=KNOWN,
                                    agents=agents, rounds=rounds, on_round=on_round, concurrency=concurrency))
    return result, calls, seen


def test_reviewers_answer_each_other_and_change_their_mind():
    def answer(name, round_no, ask):
        if name == "Skeptic" and round_no == 1:
            return position("false_positive", False, "could be an admin's test page",
                            challenges=[{"claim": "p.php is a webshell", "issue": "no command output shown",
                                         "evidence_ids": ["ev-1", "ev-99"]}],
                            missing=["apache access log for p.php"])
        if name == "Skeptic":
            assert "Threat hunter: true_positive" in ask  # sees the others' last positions
            return position("true_positive", True, "convinced by the recon commands under www-data")
        return position("true_positive", True, f"{name} agrees")

    result, calls, seen = run(answer)
    assert result["agents"] == ["Skeptic", "Threat hunter", "Evidence auditor"]
    assert [n for n, _ in seen] == [1, 2]
    first = {p["name"]: p for p in result["rounds"][0]}
    # a citation the reviewer could not have seen is dropped
    assert first["Skeptic"]["challenges"][0]["evidence_ids"] == ["ev-1"]
    assert result["tally"] == {"true_positive": 3} and result["consensus"] == "true_positive"
    # round 2 asks for responses to the others
    assert all("Answer them" in ask for _, r, ask in calls if r == 2)


def test_panel_stops_early_once_everyone_agrees():
    result, calls, _ = run(lambda name, r, ask: position("true_positive", True, "fine"), rounds=3)
    assert len(result["rounds"]) == 2  # round 1, then round 2 confirms: no third round
    assert len(calls) == 6


def test_a_failing_reviewer_sits_out_and_the_rest_go_on():
    def answer(name, round_no, ask):
        if name == "Threat hunter":
            return TimeoutError("9router timed out")
        if name == "Evidence auditor":
            return "I think it is malicious."  # no JSON
        return position("inconclusive", False, "need more")

    result, _, _ = run(answer, rounds=1)
    by = {p["name"]: p for p in result["rounds"][0]}
    assert "TimeoutError" in by["Threat hunter"]["error"]
    assert by["Evidence auditor"]["error"] == "the reply was not a JSON position"
    assert result["tally"] == {"inconclusive": 1}
    brief = debate.brief_for_lead(result, 4)
    assert "Skeptic: inconclusive" in brief and "Threat hunter" not in brief


def test_nobody_answering_gives_no_brief():
    result, _, _ = run(lambda name, r, ask: RuntimeError("down"), rounds=2)
    assert len(result["rounds"]) == 1 and result["consensus"] is None
    assert debate.brief_for_lead(result, 4) is None


def test_model_calls_are_bounded():
    gate = {"now": 0, "most": 0}
    run(lambda name, r, ask: position("true_positive", False, "x"), agents=6, rounds=1, gate=gate, concurrency=2)
    assert gate["most"] <= 2


def test_brief_lists_challenges_and_checks_and_leaves_the_verdict_to_evidence():
    def answer(name, round_no, ask):
        return position("false_positive" if name == "Skeptic" else "true_positive", name != "Skeptic", "pos",
                        challenges=[{"claim": "c-" + name, "issue": "i", "evidence_ids": ["ev-2"]}],
                        missing=["check A", "check B"] if name != "Evidence auditor" else ["check A"])
    result, _, _ = run(answer, rounds=1)
    brief = debate.brief_for_lead(result, 4)
    assert "3 reviewers debated your draft over 1 round" in brief
    assert "(Skeptic) c-Skeptic — i [ev-2]" in brief
    assert brief.count("- check A") == 1  # the same check asked twice is listed once
    assert "up to 4 more rounds" in brief and "not by a vote" in brief


@pytest.mark.parametrize("raw,verdict,confidence", [
    ({"verdict": "TRUE_POSITIVE", "confidence": "85"}, "true_positive", 85),
    ({"verdict": "maybe", "confidence": 250}, "inconclusive", 100),
    ({"confidence": "high"}, "inconclusive", 50),
])
def test_normalize_bounds_a_position(raw, verdict, confidence):
    p = debate.normalize(raw, KNOWN)
    assert (p["verdict"], p["confidence"]) == (verdict, confidence)
    assert p["challenges"] == [] and p["missing_evidence"] == []


def test_parse_position_tolerates_fences_and_prose():
    assert debate.parse_position('Here you go:\n```json\n{"verdict": "false_positive"}\n```') == {"verdict": "false_positive"}
    assert debate.parse_position("no json here") is None
    assert debate.parse_position("[1, 2]") is None


def test_panel_size_and_rounds_are_capped():
    result, calls, _ = run(lambda name, r, ask: position("true_positive", False, "x"), agents=99, rounds=99)
    assert len(result["agents"]) == debate.MAX_AGENTS and len(result["rounds"]) == debate.MAX_ROUNDS
