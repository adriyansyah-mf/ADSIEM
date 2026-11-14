"""Review panel for an AI investigation: before the lead investigator's draft
becomes the report, N reviewers with different stances read it against the
evidence ledger, challenge it, and answer each other over a few rounds. The
lead gets their final positions, may collect more evidence for what they
dispute, and then writes the report.

Pure orchestration over a chat model (ainvoke): no database, so the
investigator persists what it returns and tests drive it with a script."""
from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from typing import Any, Awaitable, Callable

from langchain_core.messages import HumanMessage, SystemMessage

# (key, name, stance). Panels take them in this order, so a small panel
# still argues both ways: the benign case and the worst case come first.
ROLES: list[tuple[str, str, str]] = [
    ("skeptic", "Skeptic",
     "Argue for the benign explanation. Look for every reason this is a false positive or overstated: "
     "administrator activity, legitimate software, scanners, misconfiguration, alerts that fired on noise. "
     "Concede only to evidence."),
    ("hunter", "Threat hunter",
     "Assume a capable attacker. Look for what the draft missed or understated: earlier and later stages, "
     "persistence, credential access, lateral movement, other hosts, data access."),
    ("auditor", "Evidence auditor",
     "Check every claim against the evidence it cites. Flag claims the cited evidence_ids do not support, "
     "conclusions that go beyond the evidence, and confidence the evidence does not justify."),
    ("responder", "Incident responder",
     "Judge impact and the recommended actions: are containment and remediation complete, proportionate "
     "and safe, what must happen first, and what the draft's actions would break."),
    ("intel", "Threat intel analyst",
     "Relate the indicators and behaviour to known tooling, campaigns and MITRE ATT&CK techniques; flag "
     "misattribution and indicators that were never enriched."),
    ("detection", "Detection engineer",
     "Ask why each stage was or was not detected, which alerts were noise, and which detection or logging "
     "gap the case shows."),
]
MAX_AGENTS = len(ROLES)
MAX_ROUNDS = 3
VERDICTS = ("true_positive", "false_positive", "inconclusive")

REPLY_FORMAT = """Reply with one JSON object and nothing else:
{"verdict": "true_positive" | "false_positive" | "inconclusive",
 "confidence": 0-100,
 "agrees_with_draft": true | false,
 "challenges": [{"claim": "the draft's statement you dispute", "issue": "why", "evidence_ids": ["..."]}],
 "missing_evidence": ["one concrete check the lead can still run, e.g. the process tree of pid 4242 on web-01"],
 "responses": [{"to": "<reviewer name>", "point": "where you agree or disagree with them, and why"}],
 "summary": "your position in at most two sentences"}

Rules: cite only evidence_id values that appear in the evidence ledger below. At most 5 challenges and
3 missing checks; an empty list is fine when you have none. Argue from your stance, but follow the
evidence: when another reviewer's evidence-backed argument convinces you, change your verdict and say so."""


def role_prompt(name: str, stance: str) -> str:
    return (f"You are the {name} on a review panel for a security investigation. The lead investigator has "
            f"written a draft report; your job is to test it before it is final, not to rewrite it.\n\n"
            f"Your stance: {stance}\n\n{REPLY_FORMAT}")


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + " …(shortened)"


def parse_position(text: str) -> dict | None:
    """The JSON object in a reviewer's reply (code fences and prose around it tolerated)."""
    if not text:
        return None
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _strs(value: Any, limit: int, size: int = 400) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clip(str(v), size) for v in value if isinstance(v, (str, int, float)) and str(v).strip()][:limit]


def normalize(raw: dict, known_ids: set[str]) -> dict:
    """A reviewer's position, bounded and with citations it could not have seen dropped."""
    verdict = str(raw.get("verdict", "")).lower().strip()
    try:
        confidence = max(0, min(100, int(float(raw.get("confidence", 50)))))
    except (TypeError, ValueError):
        confidence = 50
    challenges = []
    for c in raw.get("challenges") or []:
        if not isinstance(c, dict) or not (c.get("claim") or c.get("issue")):
            continue
        ids = [i for i in _strs(c.get("evidence_ids"), 8, 80) if not known_ids or i in known_ids]
        challenges.append({"claim": _clip(str(c.get("claim") or ""), 400),
                           "issue": _clip(str(c.get("issue") or ""), 600), "evidence_ids": ids})
    responses = [{"to": _clip(str(r.get("to") or ""), 60), "point": _clip(str(r.get("point") or ""), 500)}
                 for r in raw.get("responses") or [] if isinstance(r, dict) and r.get("point")]
    return {
        "verdict": verdict if verdict in VERDICTS else "inconclusive",
        "confidence": confidence,
        "agrees_with_draft": bool(raw.get("agrees_with_draft", False)),
        "challenges": challenges[:5],
        "missing_evidence": _strs(raw.get("missing_evidence"), 3),
        "responses": responses[:5],
        "summary": _clip(str(raw.get("summary") or ""), 500),
    }


def _others(previous: list[dict], me: str) -> str:
    lines = []
    for p in previous:
        if p["role"] == me or p.get("error"):
            continue
        lines.append(f"- {p['name']}: {p['verdict']} ({p['confidence']}%), "
                     f"{'agrees' if p['agrees_with_draft'] else 'disagrees'} with the draft. {p['summary']}")
        for c in p["challenges"]:
            lines.append(f"    challenge: {c['claim']} — {c['issue']}"
                         + (f" [{', '.join(c['evidence_ids'])}]" if c["evidence_ids"] else ""))
        for m in p["missing_evidence"]:
            lines.append(f"    wants checked: {m}")
    return "\n".join(lines) or "(no other reviewer answered)"


async def run(make_model: Callable[[], Any], *, case_brief: str, draft: str, ledger_digest: str,
              known_ids: set[str], agents: int, rounds: int,
              on_round: Callable[[int, list[dict]], Awaitable[None]] | None = None,
              concurrency: int = 3, timeout: float = 240.0) -> dict:
    """Run the panel. Each round every reviewer answers in parallel (at most
    `concurrency` model calls at once); from the second round on they see each
    other's last positions. It stops early once every reviewer agrees with the
    draft on the same verdict. A reviewer whose call fails or answers no JSON
    is recorded with an error and sits out that round."""
    roles = ROLES[:max(1, min(agents, MAX_AGENTS))]
    rounds = max(1, min(rounds, MAX_ROUNDS))
    gate = asyncio.Semaphore(max(1, concurrency))
    material = (f"Case:\n{_clip(case_brief, 8_000)}\n\nEvidence ledger:\n{_clip(ledger_digest, 16_000)}\n\n"
                f"Lead investigator's draft report:\n{_clip(draft, 12_000)}")
    transcript: list[list[dict]] = []

    async def review(key: str, name: str, stance: str, round_no: int, previous: list[dict]) -> dict:
        ask = material
        if previous:
            ask += (f"\n\nRound {round_no} of the panel. The other reviewers' positions after the last round:\n"
                    f"{_others(previous, key)}\n\nAnswer them (responses) and give your updated position.")
        else:
            ask += "\n\nRound 1 of the panel: give your position on the draft."
        base = {"role": key, "name": name}
        try:
            async with gate:
                reply = await asyncio.wait_for(
                    make_model().ainvoke([SystemMessage(content=role_prompt(name, stance)), HumanMessage(content=ask)]),
                    timeout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — one reviewer failing must not end the panel
            return {**base, "error": _clip(f"{type(exc).__name__}: {exc}", 300)}
        parsed = parse_position(str(getattr(reply, "content", "") or ""))
        if parsed is None:
            return {**base, "error": "the reply was not a JSON position"}
        return {**base, **normalize(parsed, known_ids)}

    for round_no in range(1, rounds + 1):
        previous = transcript[-1] if transcript else []
        positions = list(await asyncio.gather(*(review(k, n, s, round_no, previous) for k, n, s in roles)))
        transcript.append(positions)
        if on_round is not None:
            await on_round(round_no, positions)
        answered = [p for p in positions if not p.get("error")]
        if not answered:
            break
        if round_no > 1 and len({p["verdict"] for p in answered}) == 1 and all(p["agrees_with_draft"] for p in answered):
            break

    final = last_answers(transcript)
    tally = Counter(p["verdict"] for p in final)
    consensus = next(iter(tally)) if len(tally) == 1 and final else None
    return {"agents": [n for _, n, _ in roles], "rounds": transcript,
            "tally": dict(tally), "consensus": consensus}


def last_answers(transcript: list[list[dict]]) -> list[dict]:
    """Each reviewer's latest position that is not an error."""
    latest: dict[str, dict] = {}
    for positions in transcript:
        for p in positions:
            if not p.get("error"):
                latest[p["role"]] = p
    return list(latest.values())


def brief_for_lead(result: dict, extra_rounds: int) -> str | None:
    """What the lead is told after the panel; None when no reviewer answered."""
    final = last_answers(result.get("rounds") or [])
    if not final:
        return None
    n_rounds = len(result.get("rounds") or [])
    lines = [f"A review panel of {len(result['agents'])} reviewers debated your draft over {n_rounds} "
             f"round{'s' if n_rounds != 1 else ''}. Their final positions:"]
    for p in final:
        lines.append(f"- {p['name']}: {p['verdict']} ({p['confidence']}%), "
                     f"{'agrees' if p['agrees_with_draft'] else 'disagrees'} with your draft. {p['summary']}")
    challenges = [(p["name"], c) for p in final for c in p["challenges"]]
    if challenges:
        lines += ["", "Open challenges:"]
        for name, c in challenges[:15]:
            lines.append(f"- ({name}) {c['claim']} — {c['issue']}"
                         + (f" [{', '.join(c['evidence_ids'])}]" if c["evidence_ids"] else ""))
    wanted = list(dict.fromkeys(m for p in final for m in p["missing_evidence"]))
    if wanted:
        lines += ["", "Checks they asked for:"] + [f"- {m}" for m in wanted[:9]]
    lines += ["", (
        f"Resolve this before the report is final. You may call tools for up to {extra_rounds} more rounds to "
        "settle what they dispute; prefer the checks that would change the verdict. Then write the final JSON "
        "report: change the conclusions and confidence the evidence does not support, keep the ones it does, "
        "and put disagreements you could not settle in gaps. The verdict is yours, decided by the evidence, "
        "not by a vote.")]
    return "\n".join(lines)
