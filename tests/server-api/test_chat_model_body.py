# tests/server-api/test_chat_model_body.py
"""Non-streaming 9router responses in every shape it sends them."""
import json

import pytest

from app.core.graph.chat_model import NineRouterChatModel, parse_completion_body

COMPLETION = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}


def _sse(*objs):
    return "".join(f"data: {json.dumps(o)}\n\n" for o in objs) + "data: [DONE]\n\n"


def test_plain_json_and_json_followed_by_done():
    assert parse_completion_body(json.dumps(COMPLETION)) == COMPLETION
    assert parse_completion_body(json.dumps(COMPLETION) + "data: [DONE]") == COMPLETION


def test_sse_text_deltas_are_assembled():
    body = _sse(
        {"choices": [{"delta": {"role": "assistant", "content": "Hel"}}]},
        {"choices": [{"delta": {"content": "lo", "reasoning_content": "thinking"}}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 3}},
    )
    out = parse_completion_body(body)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "Hello" and msg["reasoning_content"] == "thinking"
    assert out["usage"] == {"prompt_tokens": 3}


def test_sse_tool_call_fragments_become_one_call():
    body = _sse(
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                "function": {"name": "run_artifact", "arguments": ""}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"artifact\": \"Linux"}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": ".Sys.Pslist\", \"host\": \"web01\"}"}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 1, "id": "call_2",
                                                "function": {"name": "list_hosts", "arguments": "{}"}}]}}]},
        {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
    )
    result = NineRouterChatModel()._to_result(parse_completion_body(body))
    calls = result.generations[0].message.tool_calls
    assert [(c["id"], c["name"], c["args"]) for c in calls] == [
        ("call_1", "run_artifact", {"artifact": "Linux.Sys.Pslist", "host": "web01"}),
        ("call_2", "list_hosts", {}),
    ]


def test_bad_bodies_say_what_came_back():
    with pytest.raises(ValueError, match="empty"):
        parse_completion_body("  ")
    with pytest.raises(ValueError, match="<html>"):
        parse_completion_body("<html><body>502 Bad Gateway</body></html>")
    with pytest.raises(ValueError, match="9router error"):
        parse_completion_body('data: {"error": {"message": "context length exceeded"}}\n\n')
