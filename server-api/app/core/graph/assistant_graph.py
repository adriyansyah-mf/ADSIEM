"""LangGraph assistant: plan → call tools → answer.

Replaces the hand-rolled ReAct loop in services/assistant.py. The graph keeps
the same guarantees as the loop it replaces:

- the tool surface is the read-only allow-list (app/core/graph/tools.py), so the
  assistant still cannot reach settings/users/webhooks;
- tool rounds are capped, and the final round forces an answer rather than
  another tool call, so a busy entity still gets a reply;
- when the model returns unusable output the caller keeps its salvage fallback.

The graph is transport-agnostic: the same compiled graph serves the blocking
endpoint (ainvoke) and the SSE endpoint (astream with stream_mode="messages").
"""
from __future__ import annotations

import json
import operator
from typing import Annotated, Literal, NotRequired, TypedDict

import structlog
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.graph import END, START, StateGraph

from app.core.graph.chat_model import NineRouterChatModel
from app.core.graph.tools import build_tools

log = structlog.get_logger()

MAX_TOOL_ROUNDS = 6

SYSTEM_PROMPT = """You are the SOC Assistant embedded in a SIEM platform, helping an analyst by answering questions using live platform data.

SCOPE: You can read alerts, cases, agents, UEBA risk scores, FIM changes, hygiene snapshots, threat hunts, detection rules, and YARA rules. You have NO access to platform settings, user accounts, or webhook configuration — if asked about those, say plainly that you don't have access to that area and suggest the analyst check the Settings/Users/Webhooks pages themselves.

You cannot take any action (you cannot close alerts, escalate cases, run commands, or change anything) — you are read-only. If asked to perform an action, explain you can only look things up and suggest what page/button to use instead.

Call the provided tools whenever you need live data — never guess at alert, case, or agent contents. You may call several tools in sequence before answering. If a tool returns an error or empty results, say so plainly rather than inventing data.

Answer in plain text, concise, no markdown headers, under 150 words — this is a chat reply, not a report."""


class AssistantState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    tool_rounds: NotRequired[int]
    tools_used: NotRequired[list[str]]
    tool_calls_made: NotRequired[list[dict]]
    answer: NotRequired[str]


def build_assistant_graph(
    *,
    db,
    group_filter: str | None,
    base_url: str,
    api_key: str,
    model: str,
    reasoning_effort: str | None = None,
    checkpointer=None,
):
    """Compile the assistant graph bound to one request's db/session scope."""
    tools = build_tools(db, group_filter)
    tools_by_name = {t.name: t for t in tools}

    llm = NineRouterChatModel(
        base_url=base_url,
        api_key=api_key,
        model=model,
        max_tokens=2200,
        reasoning_effort=reasoning_effort,
    ).bind_tools(tools)

    async def agent(state):
        rounds = state.get("tool_rounds", 0)
        messages = list(state["messages"])

        if rounds >= MAX_TOOL_ROUNDS - 1:
            messages = messages + [
                HumanMessage(content=(
                    "You have no tool calls left. Answer the analyst now in plain "
                    "text, summarising what you found even if it feels incomplete."
                ))
            ]
            plain = NineRouterChatModel(
                base_url=base_url, api_key=api_key, model=model, max_tokens=1200,
                reasoning_effort=reasoning_effort,
            )
            reply = await plain.ainvoke(messages)
            return {"messages": [reply], "answer": reply.content or ""}

        reply = await llm.ainvoke(messages)
        return {"messages": [reply]}

    async def call_tools(state):
        last = state["messages"][-1]
        used = list(state.get("tools_used", []))
        used_calls = list(state.get("tool_calls_made", []))
        out: list[BaseMessage] = []

        for call in getattr(last, "tool_calls", []) or []:
            name = call.get("name", "")
            args = call.get("args") or {}
            used.append(name)
            used_calls.append({"name": name, "args": args})
            log.info("assistant_tool_call", tool=name, args=args)
            tool = tools_by_name.get(name)
            if tool is None:
                result = {"error": f"unknown tool {name}"}
            else:
                try:
                    result = await tool.ainvoke(args)
                except Exception as exc:
                    log.warning("assistant_tool_failed", tool=name, error=str(exc))
                    result = {"error": str(exc)}
            out.append(
                ToolMessage(
                    content=json.dumps(result, default=str)[:4000],
                    tool_call_id=call.get("id") or name,
                    name=name,
                )
            )

        return {
            "messages": out,
            "tool_rounds": state.get("tool_rounds", 0) + 1,
            "tools_used": used,
            "tool_calls_made": used_calls,
        }

    def route(state) -> Literal["call_tools", "__end__"]:
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "call_tools"
        return END

    graph = StateGraph(AssistantState)
    graph.add_node("agent", agent)
    graph.add_node("call_tools", call_tools)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", route, {"call_tools": "call_tools", END: END})
    graph.add_edge("call_tools", "agent")

    return graph.compile(checkpointer=checkpointer)


def initial_messages(history: list[dict], user_message: str) -> list[BaseMessage]:
    messages: list[BaseMessage] = [SystemMessage(content=SYSTEM_PROMPT)]
    for h in history[-10:]:
        if h.get("role") == "user" and h.get("content"):
            messages.append(HumanMessage(content=str(h["content"])[:2000]))
        elif h.get("role") == "assistant" and h.get("content"):
            from langchain_core.messages import AIMessage

            messages.append(AIMessage(content=str(h["content"])[:2000]))
    messages.append(HumanMessage(content=user_message[:2000]))
    return messages
