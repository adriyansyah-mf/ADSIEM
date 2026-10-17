"""Shared graph state schemas.

Kept separate from the graph builders so the worker can import the triage state
without pulling in the assistant's tool surface, and so tests can construct
states directly.
"""
from __future__ import annotations

import operator
from typing import Annotated, Literal, NotRequired, TypedDict

from langchain_core.messages import BaseMessage


class AssistantState(TypedDict):
    """State for the interactive SOC assistant graph."""

    messages: Annotated[list[BaseMessage], operator.add]
    group_filter: NotRequired[str | None]
    tool_rounds: NotRequired[int]
    tools_used: NotRequired[list[str]]
    answer: NotRequired[str]


class TriageState(TypedDict):
    """State for the worker alert-triage graph.

    Mirrors the fields the existing ai_analyst pipeline threads through, so the
    graph can be swapped in behind a flag without changing callers.
    """

    alert_id: str
    title: str
    severity: str
    source_ip: NotRequired[str | None]
    hostname: NotRequired[str | None]
    decoded_fields: NotRequired[dict]
    group_id: NotRequired[str]

    enrichment: NotRequired[dict]
    heuristic_mitre: NotRequired[list[str]]
    search_results: NotRequired[list[dict]]
    similar_cases: NotRequired[list[dict]]
    sop_context: NotRequired[list[str]]

    verdict: NotRequired[Literal["escalate", "create_case", "monitor", "false_positive"]]
    confidence: NotRequired[float]
    triage_notes: NotRequired[str]
    mitre_techniques: NotRequired[list[str]]
    immediate_actions: NotRequired[list[str]]
    threat_type: NotRequired[str]

    case_id: NotRequired[str | None]
    case_created: NotRequired[bool]
    used_fallback: NotRequired[bool]
