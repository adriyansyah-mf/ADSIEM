"""LangChain chat model that talks to 9router.

9router is OpenAI-compatible, so this is a thin BaseChatModel implementation
rather than a dependency on langchain-openai. It reuses the gateway's retry,
429-backoff and SSE-quirk parsing so LangGraph runs and the plain gateway path
share one transport policy.

Note: this is the *graph* transport. worker/worker/llm_gateway.py and
server-api/app/core/llm_gateway.py remain the path for non-graph callers.
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx
from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    ToolMessage,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

_MESSAGE_ROLE = {
    "human": "user",
    "ai": "assistant",
    "system": "system",
    "tool": "tool",
}


def _to_openai_message(message: BaseMessage) -> dict:
    role = _MESSAGE_ROLE.get(message.type, "user")
    payload: dict[str, Any] = {"role": role, "content": message.content or ""}
    if isinstance(message, AIMessage) and message.tool_calls:
        payload["tool_calls"] = [
            {
                "id": call.get("id") or f"call_{i}",
                "type": "function",
                "function": {
                    "name": call["name"],
                    "arguments": json.dumps(call.get("args") or {}),
                },
            }
            for i, call in enumerate(message.tool_calls)
        ]
    if isinstance(message, ToolMessage):
        if message.tool_call_id:
            payload["tool_call_id"] = message.tool_call_id
        if message.name:
            payload["name"] = message.name
    return payload


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
    """A non-streaming /chat/completions response, in whichever shape 9router sends.

    9router answers with text/event-stream even when stream is false. Usually
    that's one JSON object followed by "data: [DONE]" (raw_decode reads the
    object), but for some providers — tool-calling requests in particular — it
    is a full SSE stream of deltas starting with "data:", which used to fail
    with "Expecting value: line 1 column 1". Those deltas are assembled into
    one chat.completion here.
    """
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
    seen = False
    for line in body.splitlines():
        obj = _parse_stream_line(line)
        if not obj:
            continue
        if obj.get("error"):
            raise ValueError(f"9router error in stream: {obj['error']}")
        seen = True
        usage = obj.get("usage") or usage
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
    return {"choices": [{"message": message, "finish_reason": finish}], "usage": usage}


class NineRouterChatModel(BaseChatModel):
    """Chat model backed by a 9router instance."""

    base_url: str = "http://9router:20128/v1"
    api_key: str = ""
    model: str = "combo"
    temperature: float = 0.2
    max_tokens: int = 2000
    timeout: float = 60.0
    max_retries: int = 4
    reasoning_effort: str | None = None

    @property
    def _llm_type(self) -> str:
        return "9router"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _payload(self, messages: list[BaseMessage], stream: bool) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [_to_openai_message(m) for m in messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if stream:
            payload["stream"] = True
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        if self._bound_tools:
            payload["tools"] = self._bound_tools
        return payload

    @property
    def _bound_tools(self) -> list[dict]:
        return getattr(self, "_tools_payload", []) or []

    def bind_tools(self, tools, **kwargs):  # type: ignore[override]
        payload = []
        for t in tools:
            schema = None
            raw = getattr(t, "args_schema", None)
            if isinstance(raw, dict):
                schema = raw
            elif raw is not None:
                try:
                    schema = raw.model_json_schema()
                except Exception:
                    schema = None
            payload.append({
                "type": "function",
                "function": {
                    "name": getattr(t, "name", str(t)),
                    "description": getattr(t, "description", "") or "",
                    "parameters": schema or {"type": "object", "properties": {}},
                },
            })
        clone = self.model_copy(deep=False)
        clone._tools_payload = payload  # type: ignore[attr-defined]
        return clone

    def _parse_body(self, raw: str) -> dict:
        return parse_completion_body(raw)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        import asyncio

        return asyncio.get_event_loop().run_until_complete(
            self._agenerate(messages, stop=stop, run_manager=None, **kwargs)
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        delay = 2.0
        last_exc: Exception | None = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries):
                try:
                    resp = await client.post(
                        url, headers=self._headers(), json=self._payload(messages, stream=False)
                    )
                    if resp.status_code == 429:
                        wait = min(
                            max(float(resp.headers.get("retry-after", delay)), 2.0), 20.0
                        )
                        import asyncio

                        await asyncio.sleep(wait)
                        delay = min(delay * 2, 60)
                        continue
                    resp.raise_for_status()
                    obj = self._parse_body(resp.text)
                    return self._to_result(obj)
                except Exception as exc:
                    last_exc = exc
                    if attempt == self.max_retries - 1:
                        break
                    import asyncio

                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60)

        raise RuntimeError(f"9router chat failed after {self.max_retries} attempts: {last_exc}")

    def _to_result(self, obj: dict) -> ChatResult:
        choice = obj["choices"][0]["message"]
        tool_calls = []
        for call in choice.get("tool_calls") or []:
            fn = call.get("function") or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append({
                "id": call.get("id") or f"call_{len(tool_calls)}",
                "name": fn.get("name", ""),
                "args": args or {},
            })
        message = AIMessage(
            content=choice.get("content") or "",
            tool_calls=tool_calls,
            additional_kwargs={"reasoning_content": choice.get("reasoning_content") or ""},
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _astream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[ChatGenerationChunk]:
        url = f"{self.base_url.rstrip('/')}/chat/completions"

        # Tool calls arrive as fragments (one delta per argument chunk, with
        # empty content). They are accumulated by !index and emitted as one
        # final chunk, because LangChain's ainvoke() aggregates this stream —
        # if no chunk is produced at all it raises "No generations found in
        # stream", which is what happened on every tool-calling turn.
        pending: dict[int, dict] = {}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                url,
                headers=self._headers(),
                json=self._payload(messages, stream=True),
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    obj = _parse_stream_line(line)
                    if not obj:
                        continue
                    for choice in obj.get("choices") or []:
                        delta = choice.get("delta") or {}
                        text = delta.get("content")
                        reasoning = delta.get("reasoning_content")

                        for tc in delta.get("tool_calls") or []:
                            idx = tc.get("index", 0)
                            slot = pending.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                            if tc.get("id"):
                                slot["id"] = tc["id"]
                            fn = tc.get("function") or {}
                            if fn.get("name"):
                                slot["name"] = fn["name"]
                            if fn.get("arguments"):
                                slot["arguments"] += fn["arguments"]

                        if not text and not reasoning:
                            continue

                        chunk = ChatGenerationChunk(
                            message=AIMessageChunk(
                                content=text or "",
                                additional_kwargs=(
                                    {"reasoning_content": reasoning} if reasoning else {}
                                ),
                            )
                        )
                        if run_manager:
                            await run_manager.on_llm_new_token(text or "", chunk=chunk)
                        yield chunk

        if pending:
            tool_calls = []
            for idx in sorted(pending):
                slot = pending[idx]
                if not slot["name"]:
                    continue
                try:
                    parsed_args = json.loads(slot["arguments"]) if slot["arguments"] else {}
                except json.JSONDecodeError:
                    parsed_args = {}
                tool_calls.append({
                    "id": slot["id"] or f"call_{idx}",
                    "name": slot["name"],
                    "args": parsed_args,
                })
            if tool_calls:
                final = ChatGenerationChunk(
                    message=AIMessageChunk(content="", tool_calls=tool_calls)
                )
                if run_manager:
                    await run_manager.on_llm_new_token("", chunk=final)
                yield final
