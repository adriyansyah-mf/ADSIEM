# tests/server-api/test_assistant_graph_live.py
"""Live tests for the LangGraph assistant against a real 9router deployment.

These call the actual model — nothing is mocked. They are skipped automatically
unless NINEROUTER_TEST_BASE_URL / NINEROUTER_TEST_API_KEY are set, so the normal
CI run stays hermetic.

Run locally:
    NINEROUTER_TEST_BASE_URL=... \\
    NINEROUTER_TEST_API_KEY=... \\
    NINEROUTER_TEST_MODEL=... \\
    pytest tests/server-api/test_assistant_graph_live.py -v
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("NINEROUTER_TEST_BASE_URL") and os.environ.get("NINEROUTER_TEST_API_KEY")),
    reason="live 9router not configured (set NINEROUTER_TEST_BASE_URL + NINEROUTER_TEST_API_KEY)",
)

BASE_URL = os.environ.get("NINEROUTER_TEST_BASE_URL", "")
API_KEY = os.environ.get("NINEROUTER_TEST_API_KEY", "")
MODEL = os.environ.get("NINEROUTER_TEST_MODEL", "combo")


class _EmptyResult:
    def scalars(self):
        return self

    def all(self):
        return []

    def scalar_one(self):
        return 0

    def scalar_one_or_none(self):
        return None


class _EmptyDB:
    """No rows: exercises the graph and tool plumbing without a database."""

    async def execute(self, *a, **k):
        return _EmptyResult()

    async def get(self, *a, **k):
        return None


async def test_chat_model_plain_generate():
    from langchain_core.messages import HumanMessage

    from app.core.graph.chat_model import NineRouterChatModel

    model = NineRouterChatModel(base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=60)
    result = await model._agenerate([HumanMessage(content="Reply with exactly: PONG")])
    assert "PONG" in result.generations[0].message.content.upper()


async def test_chat_model_streams_content():
    from langchain_core.messages import HumanMessage

    from app.core.graph.chat_model import NineRouterChatModel

    model = NineRouterChatModel(base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=80)
    text = ""
    async for chunk in model._astream([HumanMessage(content="Count 1 to 3, comma separated.")]):
        text += chunk.message.content or ""
    assert text.strip(), "no streamed content received"


async def test_chat_model_tool_calling():
    from langchain_core.messages import HumanMessage
    from langchain_core.tools import tool

    from app.core.graph.chat_model import NineRouterChatModel

    @tool
    def lookup_alert(alert_id: str) -> str:
        """Look up a security alert by id."""
        return "ok"

    model = NineRouterChatModel(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=300
    ).bind_tools([lookup_alert])

    reply = await model.ainvoke(
        [HumanMessage(content="Use lookup_alert for alert 12345.")]
    )
    assert reply.tool_calls, "model returned no tool call"
    assert reply.tool_calls[0]["name"] == "lookup_alert"


async def test_assistant_graph_runs_a_tool_and_answers():
    from app.core.graph.assistant_graph import build_assistant_graph, initial_messages

    graph = build_assistant_graph(
        db=_EmptyDB(),
        group_filter="default",
        base_url=BASE_URL,
        api_key=API_KEY,
        model=MODEL,
    )
    state = await graph.ainvoke(
        {"messages": initial_messages([], "Use the dashboard_stats tool, then summarise.")},
        {"configurable": {"thread_id": "live-graph-test"}},
    )

    used = state.get("tools_used") or []
    answer = state.get("answer") or (state["messages"][-1].content if state.get("messages") else "")
    assert used, "graph executed no tools"
    assert answer, "graph produced no answer"


async def test_investigative_tools_discoverable():
    from app.core.graph.tools import build_tools

    names = {t.name for t in build_tools(_EmptyDB(), "default")}
    assert {"correlate_entity", "reconstruct_timeline", "pivot_ioc"} <= names


async def test_streaming_produces_chunks_on_a_tool_call_turn():
    """Regression: _astream dropped tool-call deltas, which carry empty content,
    so LangChain's ainvoke() aggregation raised "No generations found in stream"
    on every tool-calling turn. The non-streaming path was unaffected, which is
    why this only showed up in the SOC chat widget.
    """
    from langchain_core.messages import HumanMessage

    from app.core.graph.chat_model import NineRouterChatModel
    from app.core.graph.tools import build_tools

    tools = build_tools(_EmptyDB(), "default")
    model = NineRouterChatModel(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=300
    ).bind_tools(tools)

    chunks = [
        c
        async for c in model._astream([
            HumanMessage(content="Call list_agents now. Do not answer in text.")
        ])
    ]
    assert chunks, "stream yielded no chunks — ainvoke() would raise"

    calls = [tc for c in chunks for tc in (c.message.tool_calls or [])]
    assert calls, "streamed chunks carried no tool call"


async def test_streaming_and_blocking_return_consistent_tool_calls():
    from langchain_core.messages import HumanMessage

    from app.core.graph.chat_model import NineRouterChatModel
    from app.core.graph.tools import build_tools

    tools = build_tools(_EmptyDB(), "default")
    model = NineRouterChatModel(
        base_url=BASE_URL, api_key=API_KEY, model=MODEL, max_tokens=300
    ).bind_tools(tools)
    msg = [HumanMessage(content="Call list_agents now. Do not answer in text.")]

    blocking = await model.ainvoke(msg)

    collected: list[str] = []
    async for c in model._astream(msg):
        for tc in c.message.tool_calls or []:
            collected.append(tc["name"])

    assert blocking.tool_calls, "blocking path returned no tool call"
    assert collected, "streaming path returned no tool call"
    assert collected[0] == blocking.tool_calls[0]["name"]
