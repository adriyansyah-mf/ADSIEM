# tests/worker/test_llm_body.py
"""9router answers non-streaming requests either with one JSON object or, when
a combo falls through to e.g. an ollama model, with an SSE stream of deltas.
Both must parse — the second used to fail every AI triage."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.llm_body import parse_completion_body  # noqa: E402
from worker.llm_gateway import _parse_body  # noqa: E402

# captured from production 9router, combo falling back to ollama/gemma4:31b-cloud
OLLAMA_SSE = (
    'data: {"id":"chatcmpl-1792474210318","object":"chat.completion.chunk","created":1792474210,'
    '"model":"gemma4:31b-cloud","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}\n\n'
    'data: {"id":"chatcmpl-1792474210318","object":"chat.completion.chunk","created":1792474210,'
    '"model":"gemma4:31b-cloud","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],'
    '"usage":{"prompt_tokens":18,"completion_tokens":2,"total_tokens":20}}\n\n'
)


def test_sse_deltas_are_assembled():
    obj = _parse_body(OLLAMA_SSE)
    assert obj["choices"][0]["message"]["content"] == "ok"
    assert obj["choices"][0]["finish_reason"] == "stop"
    assert obj["usage"]["total_tokens"] == 20
    assert obj["model"] == "gemma4:31b-cloud"


def test_json_followed_by_done_marker():
    raw = '{"choices":[{"message":{"content":"{\\"verdict\\":\\"monitor\\"}"}}],"usage":{}}data: [DONE]'
    assert parse_completion_body(raw)["choices"][0]["message"]["content"] == '{"verdict":"monitor"}'


def test_streamed_reasoning_and_tool_call_pieces():
    raw = "\n".join([
        'data: {"choices":[{"delta":{"reasoning_content":"think "}}]}',
        'data: {"choices":[{"delta":{"reasoning_content":"more"}}]}',
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"search","arguments":"{\\"q\\":"}}]}}]}',
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"x\\"}"}}]}}]}',
        "data: [DONE]",
    ])
    msg = parse_completion_body(raw)["choices"][0]["message"]
    assert msg["reasoning_content"] == "think more"
    assert msg["tool_calls"] == [{"id": "c1", "type": "function",
                                  "function": {"name": "search", "arguments": '{"q":"x"}'}}]


def test_errors_are_reported():
    with pytest.raises(ValueError, match="empty"):
        parse_completion_body("  ")
    with pytest.raises(ValueError, match="9router error"):
        parse_completion_body('data: {"error":{"message":"All models failed"}}')
    with pytest.raises(ValueError, match="neither JSON"):
        parse_completion_body("<html>Bad gateway</html>")
