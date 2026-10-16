# worker/worker/graph/triage_graph.py
"""LangGraph alert-triage pipeline.

Mirrors the node sequence of ai_analyst.analyze_and_maybe_create_case: enrich ->
triage -> persist notes/verdict -> SOAR -> route by verdict -> case handling.
The observable behaviour is unchanged (same verdicts, same fallbacks, same
case-dedupe); this only restructures the control flow into a graph.

Runs on 2 replicas consuming one Redis stream, so the caller wraps execution in
a per-alert lock (worker/graph/checkpoint.py::triage_lock) to prevent two
replicas from creating the same case twice.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import NotRequired, TypedDict

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from worker.graph.chat_model import NineRouterChatModel

log = structlog.get_logger()

_L1_SYSTEM_PROMPT = """You are an on-duty L1 SOC Analyst. You MUST triage EVERY alert — none are skipped.

YOUR ROLE:
- Actively investigate each alert as a real analyst working in a SOC would
- Write investigation notes as if documenting for the next shift analyst
- Make definitive decisions based on alert context, not only TI data
- If no TI data is available, apply your expertise to analyze the alert content itself

Available VERDICTs:
- "escalate"      : ACTIVE / CRITICAL threat — L2 attention required NOW
- "create_case"   : Confirmed or high-confidence threat — requires L2 investigation
- "monitor"       : Suspicious but not conclusive — acknowledge and continue monitoring
- "false_positive": Clearly benign — known scanner, internal tool, normal behavior

TRIAGE RULES:
- Alert severity critical/high → minimum "create_case", unless there is STRONG evidence of FP
- DO NOT use "false_positive" for high/critical severity without very strong justification
- If unsure between "monitor" vs "create_case", choose "create_case"

Respond ONLY with valid JSON:
{
  "verdict": "<escalate|create_case|monitor|false_positive>",
  "triage_notes": "<3-5 sentences for the next shift analyst>",
  "confidence": <0.0-1.0>,
  "mitre_techniques": ["<T-code: technique name>"],
  "immediate_actions": ["<concrete action>"],
  "false_positive_reason": "<reason if FP, null if not FP>",
  "threat_type": "<brute_force|scan|malware|c2|exfiltration|lateral_movement|privilege_escalation|other|benign>",
  "search_queries": ["<1-3 search queries>"]
}"""


class TriageState(TypedDict):
    alert_id: str
    title: str
    severity: str
    source_ip: NotRequired[str | None]
    hostname: NotRequired[str | None]
    decoded_fields: NotRequired[dict]
    group_id: NotRequired[str]

    enrichment: NotRequired[object]
    effective_severity: NotRequired[str]
    heuristic_mitre: NotRequired[list[str]]
    similar_cases: NotRequired[list]
    sop_context: NotRequired[list[str]]
    feedback_context: NotRequired[list]

    analysis: NotRequired[dict]
    verdict: NotRequired[str]
    confidence: NotRequired[float]
    triage_notes: NotRequired[str]
    search_queries: NotRequired[list[str]]

    case_id: NotRequired[str | None]
    used_fallback: NotRequired[bool]


def _extract_json(text: str) -> dict | None:
    if not text:
        return None
    content = text.strip()
    if content.startswith("```"):
        parts = content.split("```")
        if len(parts) > 1:
            content = parts[1]
        if content.startswith("json"):
            content = content[4:]
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _fallback_verdict(severity: str) -> dict:
    if severity in ("critical", "high"):
        return {
            "verdict": "create_case",
            "triage_notes": f"AI analyst unavailable. Severity {severity} alert automatically escalated for L2 review.",
            "confidence": 0.5,
            "mitre_techniques": [],
            "immediate_actions": ["Review alert manually", "Verify source IP"],
            "false_positive_reason": None,
            "threat_type": "other",
            "search_queries": [],
            "used_fallback": True,
        }
    return {
        "verdict": "monitor",
        "triage_notes": f"AI analyst unavailable. Severity {severity} alert acknowledged for continued monitoring.",
        "confidence": 0.3,
        "mitre_techniques": [],
        "immediate_actions": ["Monitor for similar alerts"],
        "false_positive_reason": None,
        "threat_type": "other",
        "search_queries": [],
        "used_fallback": True,
    }


def build_triage_graph(*, base_url: str, api_key: str, model: str, deps: dict):
    """Compile the triage graph.

    deps supplies the side-effecting helpers so the graph stays testable and the
    existing ai_analyst functions remain the single implementation of each step:
      enrich, retrieve_similar_cases, retrieve_sop_context,
      retrieve_feedback_context, suggest_mitre, escalate_severity,
      write_alert_note, tag_alert_with_mitre, set_alert_verdict,
      update_alert_status, find_existing_open_case, add_note_to_existing_case,
      create_case_from_verdict, dispatch_case_webhooks, run_soar_playbooks,
      enqueue_hunt, analyze_campaign, check_fleet_spread, run_searches,
      get_setting,
    """
    llm = NineRouterChatModel(base_url=base_url, api_key=api_key, model=model)

    async def enrich_node(state: TriageState):
        text_blob = "\n".join(filter(None, [
            state["title"], state.get("source_ip"), state.get("hostname"),
            json.dumps(state.get("decoded_fields") or {}, default=str)[:800],
        ]))
        enrichment = None
        try:
            enrichment = await deps["enrich"](text_blob, state["title"])
        except Exception as exc:
            log.warning("enrichment_failed", error=str(exc))

        effective = state["severity"]
        if enrichment and getattr(enrichment, "overall_risk", 0) > 0:
            effective = deps["escalate_severity"](state["severity"], enrichment.overall_risk)

        out: dict = {
            "enrichment": enrichment,
            "effective_severity": effective,
            "heuristic_mitre": deps["suggest_mitre"](text_blob),
        }

        query_text = f"{state['title']}\n{state.get('source_ip') or ''}\n{state.get('hostname') or ''}"
        gid = state.get("group_id", "default")
        try:
            out["similar_cases"] = await deps["retrieve_similar_cases"](query_text, gid)
            out["sop_context"] = await deps["retrieve_sop_context"](query_text, gid)
            out["feedback_context"] = await deps["retrieve_feedback_context"](query_text, gid)
        except Exception as exc:
            log.warning("rag_retrieval_failed", error=str(exc))

        if state.get("source_ip") and enrichment and getattr(enrichment, "overall_risk", 0) > 0.5:
            asyncio.ensure_future(deps["enqueue_hunt"](state["source_ip"], gid))

        return out

    async def triage_node(state: TriageState):
        prompt_parts = [
            f"ALERT TO TRIAGE:",
            f"Title    : {state['title']}",
            f"Severity : {state.get('effective_severity', state['severity'])}",
            f"Source IP: {state.get('source_ip') or 'unknown'}",
            f"Hostname : {state.get('hostname') or 'unknown'}",
            f"Fields   : {json.dumps(state.get('decoded_fields') or {}, default=str)[:500]}",
        ]
        enrichment = state.get("enrichment")
        if enrichment and getattr(enrichment, "provider_bullets", None):
            lines = "\n".join(f"  - {b}" for b in enrichment.provider_bullets[:20])
            prompt_parts.append(f"\nTHREAT INTEL:\n{lines}")
        if state.get("heuristic_mitre"):
            prompt_parts.append(f"\nHeuristic MITRE: {', '.join(state['heuristic_mitre'])}")

        try:
            reply = await llm.ainvoke([
                SystemMessage(content=_L1_SYSTEM_PROMPT),
                HumanMessage(content="\n".join(prompt_parts)),
            ])
            analysis = _extract_json(reply.content) or _fallback_verdict(
                state.get("effective_severity", state["severity"])
            )
        except Exception as exc:
            log.error("ai_l1_triage_failed", error=str(exc))
            analysis = _fallback_verdict(state.get("effective_severity", state["severity"]))

        verdict = analysis.get("verdict", "monitor")
        confidence = float(analysis.get("confidence", 0.0) or 0.0)

        try:
            threshold = float(await deps["get_setting"]("ai_confidence_threshold", "0.0"))
        except (ValueError, TypeError):
            threshold = 0.0
        if confidence < threshold and verdict not in ("monitor", "false_positive"):
            log.info("ai_low_confidence_downgrade", alert_id=state["alert_id"],
                     confidence=confidence, threshold=threshold, original_verdict=verdict)
            verdict = "monitor"

        return {
            "analysis": analysis,
            "verdict": verdict,
            "confidence": confidence,
            "triage_notes": analysis.get("triage_notes", ""),
            "search_queries": analysis.get("search_queries", []) or [],
            "used_fallback": bool(analysis.get("used_fallback")),
        }

    async def persist_node(state: TriageState):
        analysis = state.get("analysis") or {}
        verdict = state.get("verdict", "monitor")
        confidence = state.get("confidence", 0.0)
        actions = analysis.get("immediate_actions", [])
        alert_id = state["alert_id"]

        log.info("ai_l1_triage_done", alert_id=alert_id, verdict=verdict,
                 severity=state.get("effective_severity"), confidence=confidence)

        if alert_id:
            asyncio.ensure_future(deps["set_alert_verdict"](alert_id, verdict))

        actions_str = ("\n\n**Immediate Actions:**\n" + "\n".join(f"- {a}" for a in actions)) if actions else ""
        note = (
            f"## 🤖 AI L1 Triage — {verdict.upper()}\n\n"
            f"**Confidence:** {confidence:.0%}\n\n"
            f"**Investigation Notes:**\n{state.get('triage_notes','')}"
            f"{actions_str}"
        )
        await deps["write_alert_note"](alert_id, note)
        await deps["tag_alert_with_mitre"](alert_id, analysis.get("mitre_techniques", []))
        return {}

    async def soar_node(state: TriageState):
        alert_id = state["alert_id"]
        if not alert_id:
            return {}
        try:
            enrichment = state.get("enrichment")
            asyncio.ensure_future(deps["run_soar_playbooks"](
                alert_id=uuid.UUID(alert_id),
                rule_match={
                    "level": state.get("effective_severity", state["severity"]),
                    "title": state["title"],
                    "tags": (state.get("decoded_fields") or {}).get("tags", []),
                    "mitre_tags": (state.get("analysis") or {}).get("mitre_techniques", []),
                },
                source_ip=state.get("source_ip"),
                hostname=state.get("hostname"),
                user_name=(state.get("decoded_fields") or {}).get("user.name"),
                group_id=state.get("group_id", "default"),
                ai_verdict=state.get("verdict"),
                ai_confidence=state.get("confidence"),
                ti_risk_score=getattr(enrichment, "overall_risk", None) if enrichment else None,
            ))
        except Exception as exc:
            log.warning("ai_soar_dispatch_failed", alert_id=alert_id, error=str(exc))
        return {}

    async def finalize_node(state: TriageState):
        verdict = state.get("verdict", "monitor")
        alert_id = state["alert_id"]
        group_id = state.get("group_id", "default")
        queries = state.get("search_queries") or []
        source_ip = state.get("source_ip")
        hostname = state.get("hostname")

        if verdict == "false_positive":
            await deps["update_alert_status"](alert_id, "closed")
            if queries:
                asyncio.ensure_future(deps["run_searches"](alert_id, None, queries))
            log.info("alert_closed_as_fp", alert_id=alert_id,
                     reason=(state.get("analysis") or {}).get("false_positive_reason"))
            return {}

        if verdict == "monitor":
            await deps["update_alert_status"](alert_id, "acknowledged")
            if queries:
                asyncio.ensure_future(deps["run_searches"](alert_id, None, queries))
            return {}

        await deps["update_alert_status"](alert_id, "acknowledged")

        existing = await deps["find_existing_open_case"](source_ip, hostname, group_id)
        if existing:
            await deps["add_note_to_existing_case"](
                existing, alert_id, state["title"], state.get("triage_notes", ""),
                state.get("effective_severity", state["severity"]),
            )
            asyncio.ensure_future(deps["analyze_campaign"](
                trigger_alert_id=alert_id, source_ip=source_ip, hostname=hostname,
                group_id=group_id, case_id=existing,
            ))
            asyncio.ensure_future(deps["check_fleet_spread"](existing, state["title"], group_id, hostname))
            if queries:
                asyncio.ensure_future(deps["run_searches"](alert_id, existing, queries))
            return {"case_id": existing}

        case_id = await deps["create_case_from_verdict"](
            alert_id=alert_id,
            title=state["title"],
            severity=state.get("effective_severity", state["severity"]),
            verdict=verdict,
            analysis=state.get("analysis") or {},
            enrichment=state.get("enrichment"),
            group_id=group_id,
        )
        if not case_id:
            return {}

        asyncio.ensure_future(deps["analyze_campaign"](
            trigger_alert_id=alert_id, source_ip=source_ip, hostname=hostname,
            group_id=group_id, case_id=case_id,
        ))
        asyncio.ensure_future(deps["check_fleet_spread"](case_id, state["title"], group_id, hostname))
        if queries:
            asyncio.ensure_future(deps["run_searches"](alert_id, case_id, queries))

        try:
            await deps["dispatch_case_webhooks"](
                case_id=case_id,
                title=f"{'🚨 ESCALATED' if verdict == 'escalate' else '[AI]'} {state['title']}",
                severity=state.get("effective_severity", state["severity"]),
                description=(state.get("triage_notes") or "")[:500],
                group_id=group_id,
                alert_id=uuid.UUID(alert_id) if alert_id else None,
            )
        except Exception as exc:
            log.warning("case_webhook_dispatch_failed", error=str(exc))

        return {"case_id": case_id}

    graph = StateGraph(TriageState)
    graph.add_node("enrich", enrich_node)
    graph.add_node("triage", triage_node)
    graph.add_node("persist", persist_node)
    graph.add_node("soar", soar_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "enrich")
    graph.add_edge("enrich", "triage")
    graph.add_edge("triage", "persist")
    graph.add_edge("persist", "soar")
    graph.add_edge("soar", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()
