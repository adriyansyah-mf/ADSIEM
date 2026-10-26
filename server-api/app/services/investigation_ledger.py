# server-api/app/services/investigation_ledger.py
"""The investigation ledger (docs/superpowers/specs/2026-10-26-hybrid-ai-
investigation-knowledge-yara-design.md, Phase 1a): every tool call of an AI
investigation is an investigation_actions row, what it observed is
investigation_evidence the report must cite, and hypotheses link to that
evidence. The loop in investigator.py and the routes share these rules:

- The risk tier is decided here from what an action does, never by the model.
- Endpoint work (tier >= 1) is never repeated: its idempotency key is unique per
  investigation. Tier 0 queries may run again, since logs keep arriving.
- A report claim about what happened needs evidence from this investigation;
  knowledge guidance explains choices but proves nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.models.models import InvestigationAction, InvestigationEvidence, InvestigationHypothesis
from app.services.flow_artifacts import PLUGINS

# Per-investigation and per-host limits beyond investigator.py's own budgets (spec section 6.5).
HOST_CONCURRENT_FLOWS = 2     # endpoint actions running on one host, across all investigations
HOST_AUTO_FLOWS = 6           # automatic tier-1 runs per host per investigation; more need a person
MAX_ATTEMPTS = 2              # an endpoint action that failed may be tried once more

SIEM_TOOLS = {
    "get_alert", "search_alerts", "get_case", "correlate_entity", "reconstruct_timeline", "pivot_ioc",
    "search_events", "aggregate_events", "event_timeline", "recent_fim_changes", "agent_hygiene",
    "ueba_top_risky_entities", "search_sop", "search_knowledge",
}
TIER0_TOOLS = SIEM_TOOLS | {"list_hosts", "list_artifacts", "get_flow_rows", "lookup_malwarebazaar",
                            "create_artifact", "record_hypothesis"}
ENDPOINT_TOOLS = {"run_artifact", "run_command"}
# what an analyst may add to a running investigation's queue (commands keep their own approval flow)
ANALYST_TOOLS = SIEM_TOOLS | {"run_artifact"}

ACTION_OPEN = ("queued", "awaiting_approval")
KNOWLEDGE = "knowledge_guidance"

HYPOTHESIS_STATES = {"open", "supported", "refuted", "inconclusive", "superseded"}
CLOSED_STATES = HYPOTHESIS_STATES - {"open"}

VERDICTS = {"true_positive", "false_positive", "inconclusive"}
CLAIM_SECTIONS = {"timeline", "entities", "iocs", "analysis", "recommendation", "detection"}
CITED_SECTIONS = {"timeline", "entities", "iocs", "analysis"}  # facts: need evidence, not knowledge


def now() -> datetime:
    return datetime.now(timezone.utc)


def _clip(value: Any, n: int) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "…"


# ─── Actions ─────────────────────────────────────────────────────

def action_kind(tool: str) -> str:
    return {"run_artifact": "artifact", "run_command": "command", "create_artifact": "authoring",
            "record_hypothesis": "analysis"}.get(tool, "siem_query")


def split_args(args: dict) -> tuple[str | None, dict, str]:
    """A tool call's args → (target host, the parameters that define the operation, reason)."""
    params = {k: v for k, v in (args or {}).items() if k not in ("reason", "host")}
    host = args.get("host") if isinstance(args, dict) else None
    return (str(host).strip() if host else None), params, str((args or {}).get("reason") or "")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in sorted(value.items()) if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return value.strip()
    return value


def idempotency_key(tool: str, target: str | None, params: dict) -> str:
    """Same tool, same host (any case), same parameters → same operation."""
    canonical = json.dumps({"tool": tool, "target": (target or "").strip().lower(), "params": _normalize(params)},
                           sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Tier:
    tier: int
    approval_reason: str | None = None  # set when a person must approve before it runs


def artifact_tier(*, artifact: str, plugins: set[str], created_by_investigation: uuid.UUID | None,
                  promoted: bool, investigation_id: uuid.UUID, host_auto_runs: int) -> Tier:
    """Tier of running an artifact (spec section 6.2). Checks the stored content, not who wrote it."""
    if plugins - PLUGINS:
        return Tier(2, f"uses plugins outside the read-only set: {', '.join(sorted(plugins - PLUGINS))}")
    if artifact.startswith("AI.") and not promoted and created_by_investigation != investigation_id:
        return Tier(1, f"{artifact} was written by another AI investigation and has not been promoted")
    if host_auto_runs >= HOST_AUTO_FLOWS:
        return Tier(1, f"this investigation already ran {host_auto_runs} automatic collections on the host "
                       f"(limit {HOST_AUTO_FLOWS})")
    return Tier(1)


def tool_tier(tool: str) -> int:
    if tool in TIER0_TOOLS:
        return 0
    if tool == "run_artifact":
        return 1
    return 2  # run_command and anything unclassified: a person decides


async def next_ordinal(db, model, investigation_id: uuid.UUID) -> int:
    return (await db.execute(
        select(func.coalesce(func.max(model.ordinal), 0)).where(model.investigation_id == investigation_id)
    )).scalar_one() + 1


async def find_action(db, investigation_id: uuid.UUID, key: str) -> InvestigationAction | None:
    return (await db.execute(select(InvestigationAction).where(
        InvestigationAction.investigation_id == investigation_id, InvestigationAction.idempotency_key == key,
    ))).scalar_one_or_none()


def repeat_refusal(row: InvestigationAction) -> str | None:
    """Why an earlier action with this key may not run again, or None if it may."""
    if row.status == "skipped":
        why = f" ({row.decision_note})" if row.decision_note else ""
        return (f"an analyst skipped or rejected this exact action (#{row.ordinal}){why}. "
                "Don't ask for it again; adapt or write the report.")
    if row.status == "cancelled":
        return f"this exact action (#{row.ordinal}) was cancelled; don't ask for it again"
    if row.risk_tier >= 1 and row.status == "completed":
        ids = ", ".join(row.result_ref.get("evidence_ids", [])[:6]) if row.result_ref else ""
        return (f"this exact collection already ran as action #{row.ordinal}"
                f"{' (evidence ' + ids + ')' if ids else ''}; use its result or get_flow_rows instead of re-running")
    if row.risk_tier >= 1 and row.status == "failed" and row.attempts >= MAX_ATTEMPTS:
        return f"this exact action failed {row.attempts} times (last: {row.error}); try something else"
    return None


# ─── Evidence ────────────────────────────────────────────────────

@dataclass
class EvidenceSpec:
    evidence_type: str
    source_type: str
    source_id: str
    title: str
    summary: str
    payload: Any
    entities: dict = field(default_factory=dict)
    sensitivity: str = "normal"
    observed_at: datetime | None = None
    attach: tuple = ()  # where the id goes in the tool result: () = top level, ("sources", 2) = that source


def content_hash(spec: EvidenceSpec) -> str:
    body = json.dumps([spec.evidence_type, spec.source_type, spec.source_id, spec.payload],
                      sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def is_success(result: Any) -> bool:
    """A tool result that is not an error. Flow summaries always carry an `error` key, None when it ran fine."""
    return isinstance(result, dict) and not result.get("error")


def evidence_specs(tool: str, args: dict, result: Any) -> list[EvidenceSpec]:
    """What a tool result observed. Errors, listings and authoring observe nothing."""
    if not is_success(result):
        return []
    host = str((args or {}).get("host") or "")
    if tool == "run_artifact":
        flow_id, artifact = result.get("flow_id", ""), result.get("artifact", args.get("artifact", ""))
        out = []
        for i, src in enumerate(result.get("sources") or []):
            n = src.get("total_rows", 0)
            out.append(EvidenceSpec(
                "flow_row", "flow", f"{flow_id}:{src.get('source')}",
                _clip(f"{artifact} · {src.get('source')} on {host}", 300),
                f"{n} rows (flow {result.get('status')})" + (f"; first: {_clip(src.get('rows', [])[:3], 1200)}" if n else ""),
                {"flow": flow_id, "source": src.get("source"), "total": n, "rows": src.get("rows", [])[:20]},
                {"hosts": [host]} if host else {}, attach=("sources", i)))
        return out
    if tool == "get_flow_rows":
        key = f"{result.get('flow_id')}:{result.get('source')}:{args.get('contains', '')}:{result.get('offset', 0)}"
        return [EvidenceSpec(
            "flow_row", "flow", key,
            _clip(f"Flow rows {result.get('source')}" + (f" matching '{args.get('contains')}'" if args.get("contains") else ""), 300),
            f"{result.get('matching_rows', 0)} matching rows; first: {_clip(result.get('rows', [])[:3], 1200)}",
            {"key": key, "rows": result.get("rows", [])[:20]})]
    if tool == "run_command":
        if not result.get("flow_id"):
            return []
        return [EvidenceSpec(
            "command_result", "command", str(result["flow_id"]), _clip(f"{result.get('command')} on {result.get('host')}", 300),
            f"{result.get('exit') or result.get('status')}; stdout: {_clip(result.get('stdout', ''), 1200)}",
            {"flow": result["flow_id"], "stdout": result.get("stdout"), "stderr": result.get("stderr"), "exit": result.get("exit")},
            {"hosts": [str(result.get("host") or "")]}, sensitivity="sensitive")]
    if tool == "lookup_malwarebazaar":
        if result.get("status") in ("disabled", "unconfigured"):
            return []
        h = str(result.get("queried_hash") or "")
        return [EvidenceSpec("ti_result", "malwarebazaar", h, _clip(f"MalwareBazaar {result.get('status')} for {h[:16]}…", 300),
                             _clip({k: v for k, v in result.items() if k != "raw"}, 1500), result, {"hashes": [h]})]
    if tool in ("search_knowledge", "search_sop"):
        notes = [n for n in result.get("notes") or [] if isinstance(n, dict) and n.get("id")]
        ids = [str(n["id"]) for n in notes]
        titles = {str(n["id"]): str(n.get("title") or "") for n in notes}
        headings = {str(n["id"]): n.get("heading") for n in notes if n.get("heading")}
        return [EvidenceSpec(KNOWLEDGE, tool, _clip(args.get("query", ""), 255),
                             _clip(f"Knowledge: {args.get('query', '')}", 300),
                             _clip("; ".join(t for t in titles.values() if t) or result, 1500), result,
                             {"knowledge_ids": ids, "titles": titles, "headings": headings})]
    if tool in SIEM_TOOLS and tool != "get_case":
        etype = "alert" if tool in ("get_alert", "search_alerts") else "event"
        source_id = str(result.get("id")) if tool == "get_alert" and result.get("id") else \
            f"{tool}:{idempotency_key(tool, None, args)[:16]}"
        return [EvidenceSpec(etype, "alert" if tool == "get_alert" else "siem_query", source_id,
                             _clip(f"{tool} {_clip(args, 200)}", 300), _clip(result, 1500), result)]
    return []


def attach_ids(result: dict, specs: list[EvidenceSpec], ids: list[uuid.UUID]) -> None:
    """Put each evidence id where the model reads the observation, so its report can cite it."""
    for spec, eid in zip(specs, ids):
        target: Any = result
        if spec.attach:
            container, index = spec.attach
            target = (result.get(container) or [None] * (index + 1))[index]
        if isinstance(target, dict):
            target["evidence_id"] = str(eid)


async def record_evidence(db, *, investigation_id: uuid.UUID, group_id: str, action_id: uuid.UUID | None,
                          spec: EvidenceSpec) -> uuid.UUID:
    """Insert once per (investigation, content): the same observation keeps one id."""
    digest = content_hash(spec)
    row = await db.execute(insert(InvestigationEvidence).values(
        id=uuid.uuid4(), investigation_id=investigation_id, action_id=action_id, group_id=group_id,
        evidence_type=spec.evidence_type, source_type=spec.source_type, source_id=spec.source_id[:255],
        title=spec.title[:300], summary=spec.summary, observed_at=spec.observed_at or now(),
        entities=spec.entities, content_hash=digest, sensitivity=spec.sensitivity, pinned=False,
        created_at=now(), updated_at=now(),
    ).on_conflict_do_nothing(constraint="uq_investigation_evidence_hash").returning(InvestigationEvidence.id))
    eid = row.scalar_one_or_none()
    if eid is None:
        eid = (await db.execute(select(InvestigationEvidence.id).where(
            InvestigationEvidence.investigation_id == investigation_id, InvestigationEvidence.content_hash == digest,
        ))).scalar_one()
    return eid


async def evidence_index(db, investigation_id: uuid.UUID) -> dict[str, InvestigationEvidence]:
    rows = (await db.execute(select(InvestigationEvidence).where(
        InvestigationEvidence.investigation_id == investigation_id))).scalars().all()
    return {str(r.id): r for r in rows}


# ─── Hypotheses ──────────────────────────────────────────────────

class HypothesisError(ValueError):
    pass


def _ids(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [v for v in re.split(r"[,\s]+", values) if v]
    return [str(v).strip() for v in values if str(v).strip()]


def check_evidence_ids(ids: list[str], index: dict[str, InvestigationEvidence]) -> None:
    for eid in ids:
        ev = index.get(eid)
        if ev is None:
            raise HypothesisError(f"evidence {eid} is not from this investigation")
        if ev.evidence_type == KNOWLEDGE:
            raise HypothesisError(f"evidence {eid} is knowledge guidance; it cannot support or refute a hypothesis")


def apply_hypothesis_update(h: InvestigationHypothesis, *, actor: str, index: dict[str, InvestigationEvidence],
                            state: str | None = None, confidence: Any = None, supporting: Any = None,
                            contradicting: Any = None, open_questions: Any = None, reason: str = "") -> dict:
    """Apply an update under the section 7.3 rules; returns the history entry it appended."""
    supporting_ids, contradicting_ids = _ids(supporting), _ids(contradicting)
    check_evidence_ids(supporting_ids + contradicting_ids, index)
    h.supporting_evidence_ids = list(dict.fromkeys([*(h.supporting_evidence_ids or []), *supporting_ids]))
    h.contradicting_evidence_ids = list(dict.fromkeys([*(h.contradicting_evidence_ids or []), *contradicting_ids]))
    if open_questions is not None:
        h.open_questions = [str(q)[:300] for q in (open_questions if isinstance(open_questions, list) else [open_questions])][:10]
    entry: dict[str, Any] = {"at": now().isoformat(), "actor": actor, "reason": reason[:500]}
    if confidence is not None:
        try:
            h.confidence = max(0, min(100, int(confidence)))
        except (TypeError, ValueError):
            raise HypothesisError("confidence must be a number from 0 to 100")
    if state is not None and state != h.state:
        if state not in HYPOTHESIS_STATES:
            raise HypothesisError(f"state must be one of {sorted(HYPOTHESIS_STATES)}")
        if state == "supported" and not h.supporting_evidence_ids:
            raise HypothesisError("a supported hypothesis needs supporting evidence ids")
        if state == "refuted" and not h.contradicting_evidence_ids:
            raise HypothesisError("a refuted hypothesis needs contradicting evidence ids")
        if h.source == "analyst" and actor == "ai" and state in CLOSED_STATES:
            entry["proposed_state"] = state  # an analyst's hypothesis is closed by an analyst
        else:
            h.state = state
    entry.update(state=h.state, confidence=h.confidence)
    h.history = [*(h.history or []), entry]
    return entry


async def new_hypothesis(db, *, investigation_id: uuid.UUID, group_id: str, statement: str,
                         source: str) -> InvestigationHypothesis:
    statement = (statement or "").strip()
    if not statement:
        raise HypothesisError("statement is required")
    h = InvestigationHypothesis(
        investigation_id=investigation_id, group_id=group_id, statement=statement[:1000], source=source,
        ordinal=await next_ordinal(db, InvestigationHypothesis, investigation_id), state="open", confidence=50,
        supporting_evidence_ids=[], contradicting_evidence_ids=[], open_questions=[], history=[],
    )
    db.add(h)
    return h


# ─── Structured report ───────────────────────────────────────────

REPORT_SCHEMA_PROMPT = """{
  "verdict": "true_positive | false_positive | inconclusive",
  "confidence": 0-100,
  "executive_summary": "2-4 sentences",
  "claims": [
    {"id": "c1", "section": "timeline | entities | iocs | analysis | recommendation | detection",
     "text": "one finding; timeline claims start with the timestamp",
     "evidence_ids": ["<evidence_id from a tool result or the case context>"],
     "contradicting_evidence_ids": []}
  ],
  "gaps": ["what you could not check and why"],
  "recommended_actions": ["containment / remediation for the operator, most urgent first"],
  "detection_opportunities": ["..."],
  "knowledge_citations": [{"entry_id": "<knowledge note id from search_knowledge>", "heading": "..."}]
}"""

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.S)


def parse_report(content: str) -> dict | None:
    """The JSON report in a final message (bare, fenced, or with prose around it), else None."""
    text = _FENCE.sub("", (content or "").strip())
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) and ("claims" in obj or "verdict" in obj) else None


def _str_list(value: Any, limit: int = 30) -> list[str]:
    if isinstance(value, str):
        value = [value]
    return [str(v)[:1000] for v in (value or []) if str(v).strip()][:limit] if isinstance(value, list) else []


def validate_report(raw: dict, index: dict[str, InvestigationEvidence],
                    knowledge_ids: set[str]) -> tuple[dict, list[str]]:
    """Normalize a report and list what breaks the citation rules (spec section 8.1).
    Every claim comes back with `verified`; problems drive the one repair attempt."""
    problems: list[str] = []
    verdict = str(raw.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        problems.append(f"verdict must be one of {sorted(VERDICTS)}, got {verdict or 'nothing'}")
        verdict = "inconclusive"
    try:
        confidence = max(0, min(100, int(raw.get("confidence", 0))))
    except (TypeError, ValueError):
        problems.append("confidence must be a number from 0 to 100")
        confidence = 0
    claims = []
    raw_claims = raw.get("claims") if isinstance(raw.get("claims"), list) else []
    if not isinstance(raw.get("claims"), list):
        problems.append("claims must be a list")
    for i, c in enumerate(raw_claims[:80]):
        if not isinstance(c, dict) or not str(c.get("text") or "").strip():
            problems.append(f"claim {i + 1} has no text")
            continue
        cid = str(c.get("id") or f"c{i + 1}")[:20]
        section = str(c.get("section") or "analysis").lower()
        if section not in CLAIM_SECTIONS:
            section = "analysis"
        cited, against, issues = _ids(c.get("evidence_ids")), _ids(c.get("contradicting_evidence_ids")), []
        for eid in cited + against:
            ev = index.get(eid)
            if ev is None:
                issues.append(f"{eid} is not evidence from this investigation")
            elif ev.evidence_type == KNOWLEDGE and section in CITED_SECTIONS:
                issues.append(f"{eid} is knowledge guidance, which cannot prove a claim in {section}")
        proof = [e for e in cited if e in index and (index[e].evidence_type != KNOWLEDGE or section not in CITED_SECTIONS)]
        if section in CITED_SECTIONS and not proof:
            issues.append("cites no evidence from this investigation")
        claims.append({"id": cid, "section": section, "text": str(c["text"]).strip()[:2000],
                       "evidence_ids": [e for e in cited if e in index],
                       "contradicting_evidence_ids": [e for e in against if e in index],
                       "verified": not issues, "issues": issues})
        problems += [f"claim {cid} ({section}): {msg}" for msg in issues]
    citations = []
    for k in raw.get("knowledge_citations") or []:
        if not isinstance(k, dict):
            continue
        entry = str(k.get("entry_id") or "")
        if entry in knowledge_ids:
            citations.append({"entry_id": entry, "heading": str(k.get("heading") or "")[:200]})
        else:
            problems.append(f"knowledge citation {entry or '?'} was not retrieved by this investigation")
    report = {
        "verdict": verdict, "confidence": confidence,
        "executive_summary": str(raw.get("executive_summary") or "").strip()[:4000],
        "claims": claims, "gaps": _str_list(raw.get("gaps")),
        "recommended_actions": _str_list(raw.get("recommended_actions")),
        "detection_opportunities": _str_list(raw.get("detection_opportunities")),
        "knowledge_citations": citations, "citations_unchecked": False,
    }
    return report, problems


def finalize_report(report: dict) -> dict:
    """After the repair attempt: a verdict resting only on unverified claims becomes inconclusive."""
    facts = [c for c in report["claims"] if c["section"] in CITED_SECTIONS]
    if report["verdict"] != "inconclusive" and not any(c["verified"] for c in facts):
        report["verdict_downgraded_from"] = report["verdict"]
        report["verdict"] = "inconclusive"
    report["unverified_claims"] = sum(1 for c in report["claims"] if not c["verified"])
    return report


def render_markdown(report: dict, index: dict[str, InvestigationEvidence]) -> str:
    """The Markdown kept on the investigation and in the case note, with evidence footnotes."""
    labels: dict[str, str] = {}

    def refs(claim: dict) -> str:
        out = []
        for eid in claim["evidence_ids"]:
            labels.setdefault(eid, f"E{len(labels) + 1}")
            out.append(f"[{labels[eid]}]")
        for eid in claim["contradicting_evidence_ids"]:
            labels.setdefault(eid, f"E{len(labels) + 1}")
            out.append(f"[against {labels[eid]}]")
        return (" " + " ".join(out)) if out else ""

    verified = [c for c in report["claims"] if c["verified"]]
    lines = ["## Summary", report["executive_summary"] or "_No summary._", "",
             f"**Verdict:** {report['verdict'].replace('_', ' ')} · confidence {report['confidence']}%"]
    if report.get("verdict_downgraded_from"):
        lines.append(f"_Downgraded from {report['verdict_downgraded_from'].replace('_', ' ')}: "
                     "none of the supporting claims cite evidence from this investigation._")
    for section, title in (("analysis", "Findings"), ("timeline", "Timeline"), ("entities", "Affected entities"),
                           ("iocs", "Indicators")):
        items = [c for c in verified if c["section"] == section]
        if items:
            lines += ["", f"## {title}", *[f"- {c['text']}{refs(c)}" for c in items]]
    recs = report["recommended_actions"] + [c["text"] + refs(c) for c in verified if c["section"] == "recommendation"]
    if recs:
        lines += ["", "## Recommended actions", *[f"{i}. {r}" for i, r in enumerate(recs, 1)]]
    dets = report["detection_opportunities"] + [c["text"] + refs(c) for c in verified if c["section"] == "detection"]
    if dets:
        lines += ["", "## Detection opportunities", *[f"- {d}" for d in dets]]
    if report["gaps"]:
        lines += ["", "## Gaps", *[f"- {g}" for g in report["gaps"]]]
    unverified = [c for c in report["claims"] if not c["verified"]]
    if unverified:
        lines += ["", "## Unverified statements",
                  "_These claims do not cite evidence this investigation collected; treat them as leads._",
                  *[f"- ⚠ {c['text']}{refs(c)}" for c in unverified]]
    if labels:
        lines += ["", "## Evidence"]
        for eid, label in labels.items():
            ev = index.get(eid)
            lines.append(f"- **{label}** {ev.title if ev else eid} (`{eid}`)")
    if report["knowledge_citations"]:
        titles = {k: t for ev in index.values() if ev.evidence_type == KNOWLEDGE
                  for k, t in ((ev.entities or {}).get("titles") or {}).items()}
        lines += ["", "## Knowledge cited",
                  *[f"- Knowledge: {titles.get(k['entry_id']) or k['entry_id']}{'#' + k['heading'] if k['heading'] else ''}"
                    for k in report["knowledge_citations"]]]
    lines += ["", f"VERDICT: {report['verdict']}"]
    return "\n".join(lines)


def knowledge_ids_seen(index: dict[str, InvestigationEvidence]) -> set[str]:
    return {k for ev in index.values() if ev.evidence_type == KNOWLEDGE for k in (ev.entities or {}).get("knowledge_ids", [])}
