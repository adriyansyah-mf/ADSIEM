# worker/worker/graph/chat_model.py
"""LangChain chat model over 9router for the worker's graphs.

Mirrors server-api/app/core/graph/chat_model.py. The two services are separate
containers with separate image roots, so this is a deliberate per-service copy
rather than a cross-service import — the same pattern as llm_gateway.py.
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator

import asyncio
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


class NineRouterChatModel(BaseChatModel):
    base_url: str = "http://9router:20128/v1"
    api_key: str = ""
    model: str = "combo"
    temperature: float = 0.15
    max_tokens: int = 2500
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
        return payload

    def _parse_body(self, raw: str) -> dict:
        if not raw or not raw.strip():
            raise ValueError("empty response body")
        obj, _ = json.JSONDecoder().raw_decode(raw)
        return obj

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
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
                        wait = min(max(float(resp.headers.get("retry-after", delay)), 2.0), 20.0)
                        await asyncio.sleep(wait)
                        delay = min(delay * 2, 60)
                        continue
                    resp.raise_for_status()
                    return self._to_result(self._parse_body(resp.text))
                except Exception as exc:
                    last_exc = exc
                    if attempt == self.max_retries - 1:
                        break
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
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST", url, headers=self._headers(), json=self._payload(messages, stream=True)
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
