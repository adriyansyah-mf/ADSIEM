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
    return {"reply": str(answer)[:2000], "tools_used": state.get("tools_used") or []}


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

    try:
        async for chunk in graph.astream(payload, config, stream_mode="messages"):
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
    except Exception as exc:
        log.warning("assistant_stream_failed", error=str(exc))
        yield {"type": "error", "message": str(exc)}
        return

    yield {"type": "finish"}
