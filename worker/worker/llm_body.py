# worker/worker/llm_body.py
"""A non-streaming /chat/completions response, in whichever shape 9router sends.

9router answers with text/event-stream even when stream is false. Usually that
is one JSON object followed by "data: [DONE]" (raw_decode reads the object).
When a combo falls through to some providers — ollama models in particular, or
tool-calling requests — it is a full SSE stream of chat.completion.chunk deltas
starting with "data:", which failed with "Expecting value: line 1 column 1" and
left every AI triage "unavailable". Those deltas are assembled into one
chat.completion here.

Same logic as server-api/app/core/graph/chat_model.py parse_completion_body;
no dependencies, so every worker LLM caller can share it.
"""
from __future__ import annotations

import json
from typing import Any


def _parse_stream_line(line: str) -> dict | None:
    line = (line or "").strip()
    if not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if not data or data == "[DONE]":
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None


def parse_completion_body(raw: str) -> dict:
    body = (raw or "").strip()
    if not body:
        raise ValueError("empty response body")
    if body.startswith("{"):
        obj, _ = json.JSONDecoder().raw_decode(body)
        return obj
    if body.startswith(("data:", "event:", ":")):
        return _assemble_sse(body)
    raise ValueError(f"response is neither JSON nor an event stream: {body[:200]!r}")


def _assemble_sse(body: str) -> dict:
    content: list[str] = []
    reasoning: list[str] = []
    calls: dict[int, dict] = {}
    usage: dict = {}
    finish = None
    model = None
    seen = False
    for line in body.splitlines():
        obj = _parse_stream_line(line)
        if not obj:
            continue
        if obj.get("error"):
            raise ValueError(f"9router error in stream: {obj['error']}")
        seen = True
        usage = obj.get("usage") or usage
        model = obj.get("model") or model
        for choice in obj.get("choices") or []:
            finish = choice.get("finish_reason") or finish
            # a provider may also send whole messages instead of deltas
            delta = choice.get("delta") or choice.get("message") or {}
            if delta.get("content"):
                content.append(delta["content"])
            if delta.get("reasoning_content"):
                reasoning.append(delta["reasoning_content"])
            for pos, tc in enumerate(delta.get("tool_calls") or []):
                slot = calls.setdefault(tc.get("index", pos), {"id": "", "name": "", "arguments": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    args = fn["arguments"]
                    slot["arguments"] += args if isinstance(args, str) else json.dumps(args)
    if not seen:
        raise ValueError(f"event stream without data: {body[:200]!r}")
    message: dict[str, Any] = {"role": "assistant", "content": "".join(content)}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if calls:
        message["tool_calls"] = [
            {"id": s["id"] or f"call_{i}", "type": "function",
             "function": {"name": s["name"], "arguments": s["arguments"] or "{}"}}
            for i, s in sorted(calls.items()) if s["name"]
        ]
    out: dict[str, Any] = {"choices": [{"message": message, "finish_reason": finish}], "usage": usage}
    if model:
        out["model"] = model
    return out
