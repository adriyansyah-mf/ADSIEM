# server-api/app/services/assistant.py
"""Read-only SOC chat assistant, driven by the LangGraph assistant graph.

The assistant can only reach the read-only tool allow-list
(app/services/assistant_tools.py); settings, users and webhooks are never
imported on this path.
"""
from __future__ import annotations

from typing import AsyncIterator

import structlog
from langchain_core.messages import AIMessageChunk
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.graph.assistant_graph import (
    build_assistant_graph,
    initial_messages,
)
from app.models.models import PlatformSetting

log = structlog.get_logger()

_TOOL_ROUTES: dict[str, tuple[str, str]] = {
    "search_alerts": ("/alerts", "Open alerts"),
    "get_alert": ("/alerts", "Open alerts"),
    "search_cases": ("/cases", "Open cases"),
    "get_case": ("/cases", "Open cases"),
    "list_agents": ("/agents", "Open agents"),
    "agent_hygiene": ("/hygiene", "Open hygiene"),
    "recent_fim_changes": ("/fim", "Open FIM"),
    "ueba_top_risky_entities": ("/ueba", "Open UEBA"),
    "list_threat_hunts": ("/hunts", "Open hunts"),
    "search_rules": ("/rules", "Open rules"),
    "yara_rule_status": ("/yara", "Open YARA rules"),
    "search_events": ("/events", "Open events"),
    "aggregate_events": ("/events", "Open events"),
    "event_timeline": ("/live-events", "Open live events"),
    "mitre_coverage": ("/mitre-heatmap", "Open MITRE heatmap"),
    "list_soar_playbooks": ("/soar", "Open SOAR"),
    "search_sop": ("/sop", "Open SOP"),
    "list_decoders": ("/decoders", "Open decoders"),
    "list_log_sources": ("/agents", "Open agents"),
    "list_tasks": ("/live-response", "Open live response"),
    "search_audit_logs": ("/audit-logs", "Open audit logs"),
    "handover_summary": ("/handover", "Open handover"),
}

_QUERY_PARAM_MAP: dict[str, dict[str, str]] = {
    "search_alerts": {"status": "status", "severity": "severity", "hostname": "hostname", "source_ip": "source_ip"},
    "search_cases": {"status": "status", "severity": "severity"},
    "list_agents": {"status": "status"},
    "search_rules": {"query": "search"},
    "recent_fim_changes": {"hostname": "hostname"},
    "search_events": {"source_ip": "source_ip", "log_type": "event_action", "search": "search"},
    "search_audit_logs": {"action": "action"},
    "list_tasks": {"status": "status"},
    "list_decoders": {"log_type": "log_type"},
    "list_log_sources": {"hostname": "hostname"},
    "agent_hygiene": {"hostname": "hostname"},
}

_ENTITY_ROUTES: dict[str, str] = {
    "get_case": "/cases",
}


def navigation_actions(tool_calls: list[dict] | list[str]) -> list[dict]:
    """Turn the tool calls a turn made into parameterised dashboard links.

    Each action carries the query parameters the assistant searched with, so
    "tampilkan agents yang offline" opens /agents?status=offline rather than a
    bare list. Alert detail is a modal in the dashboard, not a route, so an
    alert id becomes a filter param rather than a path segment.
    """
    actions: list[dict] = []
    seen: set[str] = set()

    calls: list[dict] = []
    for entry in tool_calls or []:
        if isinstance(entry, str):
            calls.append({"name": entry, "args": {}})
        elif isinstance(entry, dict):
            calls.append(entry)

    for call in calls:
        name = call.get("name", "")
        args = call.get("args") or {}
        target = _TOOL_ROUTES.get(name)
        if not target:
            continue
        base, label = target

        query: dict[str, str] = {}
        for arg_key, param in _QUERY_PARAM_MAP.get(name, {}).items():
            value = args.get(arg_key)
            if value not in (None, ""):
                query[param] = str(value)

        if name == "get_alert" and args.get("alert_id"):
            query.setdefault("alert_id", str(args["alert_id"]))

        entity = args.get("case_id") if name in _ENTITY_ROUTES else None
        path = f"{_ENTITY_ROUTES[name]}/{entity}" if entity else base

        if query:
            from urllib.parse import urlencode
            path = f"{path}?{urlencode(query)}"

        if path in seen:
            continue
        seen.add(path)

        action: dict = {"label": label, "to": path}
        if query:
            action["params"] = query
        if entity:
            action["entity_id"] = str(entity)
        actions.append(action)

    return actions


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (
        await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))
    ).scalar_one_or_none()
    return row.value if row and row.value else default


async def _graph_config(db: AsyncSession, group_filter: str | None):
    from app.core.config import settings

    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "") or settings.LANGGRAPH_ASSISTANT_MODEL
    effort = await _get_setting(db, "assistant_reasoning_effort", "") or (
        settings.ASSISTANT_REASONING_EFFORT or None
    )
    if not model:
        model = "combo"
    return api_key, model, effort


async def run_assistant_chat(
    db: AsyncSession,
    group_filter: str | None,
    history: list[dict],
    user_message: str,
) -> dict:
    from app.core.config import settings

    api_key, model, effort = await _graph_config(db, group_filter)
    if not api_key:
        return {
            "reply": "The AI assistant isn't configured yet — an admin needs to set the 9router API key in Settings.",
            "tools_used": [],
            "actions": [],
        }

    graph = build_assistant_graph(
        db=db,
        group_filter=group_filter,
        base_url=settings.NINEROUTER_BASE_URL,
        api_key=api_key,
        model=model,
        reasoning_effort=effort,
    )
    state = await graph.ainvoke(
        {"messages": initial_messages(history, user_message)},
        {"configurable": {"thread_id": f"assistant-{id(db)}-{abs(hash(user_message)) % 100000}"}},
    )
    answer = state.get("answer") or (state["messages"][-1].content if state.get("messages") else "")
    used = state.get("tools_used") or []
    calls = state.get("tool_calls_made") or used
    return {
        "reply": str(answer)[:2000],
        "tools_used": used,
        "actions": navigation_actions(calls),
    }


async def stream_assistant_chat(
    db: AsyncSession,
    group_filter: str | None,
    history: list[dict],
    user_message: str,
) -> AsyncIterator[dict]:
    """Stream the graph's tokens as the same chunk types the gateway emits."""
    from app.core.config import settings

    api_key, model, effort = await _graph_config(db, group_filter)
    if not api_key:
        yield {
            "type": "error",
            "message": "The AI assistant isn't configured yet — an admin needs to set the 9router API key in Settings.",
        }
        return

    graph = build_assistant_graph(
        db=db,
        group_filter=group_filter,
        base_url=settings.NINEROUTER_BASE_URL,
        api_key=api_key,
        model=model,
        reasoning_effort=effort,
    )

    yield {"type": "start", "model": model}

    payload = {"messages": initial_messages(history, user_message)}
    config = {"configurable": {"thread_id": f"assistant-stream-{id(db)}-{abs(hash(user_message)) % 100000}"}}
    final_state: dict | None = None

    try:
        async for mode, chunk in graph.astream(
            payload, config, stream_mode=["messages", "values"]
        ):
            if mode == "messages":
                message, metadata = chunk
                if not isinstance(message, AIMessageChunk):
                    continue
                if metadata.get("langgraph_node") != "agent":
                    continue
                reasoning = (message.additional_kwargs or {}).get("reasoning_content")
                if reasoning:
                    yield {"type": "reasoning-delta", "text": reasoning}
                if message.content:
                    yield {"type": "text-delta", "text": message.content}
            elif mode == "values":
                final_state = chunk
    except Exception as exc:
        log.warning("assistant_stream_failed", error=str(exc))
        yield {"type": "error", "message": str(exc)}
        return

    if final_state:
        calls = final_state.get("tool_calls_made") or final_state.get("tools_used") or []
        actions = navigation_actions(calls)
        if actions:
            yield {"type": "actions", "actions": actions}

    yield {"type": "finish"}
