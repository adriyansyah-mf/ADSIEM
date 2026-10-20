# worker/worker/llm_gateway.py
"""Single LLM gateway for the worker.

Consolidates the retry / 429-backoff / SSE-quirk parsing / fallback logic that
was previously duplicated across worker/llm_client.py, worker/ninerouter_search.py
and the two callers that reached into llm_client's private _llm_post
(hunter.py, report_sender.py).

Calls go to 9router, which is OpenAI-compatible, so a provider is just a
(base_url, api_key, model) triple. Fallbacks are ordered model aliases tried in
sequence when the primary is rate-limited or failing.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Iterable

import httpx
import structlog
from prometheus_client import Counter, Histogram

from worker.config import NINEROUTER_API_KEY, NINEROUTER_BASE_URL, NINEROUTER_MODEL
from worker.llm_body import parse_completion_body
from worker.settings_cache import get_setting

log = structlog.get_logger()

_SERVICE = "worker"

llm_requests_total = Counter(
    "siem_llm_requests_total",
    "LLM requests by outcome",
    ["service", "model", "outcome"],
)
llm_tokens_total = Counter(
    "siem_llm_tokens_total",
    "LLM tokens consumed",
    ["service", "model", "kind"],
)
llm_latency_seconds = Histogram(
    "siem_llm_latency_seconds",
    "LLM request latency",
    ["service", "model"],
)
llm_fallbacks_total = Counter(
    "siem_llm_fallbacks_total",
    "Provider fallbacks taken",
    ["service", "from_model", "to_model"],
)

_MAX_ATTEMPTS = 4
_MAX_RATE_LIMIT_WAIT = 20.0
_MAX_BACKOFF = 60.0
_DEFAULT_TIMEOUT = 40.0

_llm_semaphore = asyncio.Semaphore(3)


class LLMError(RuntimeError):
    """Raised when every attempt and every fallback has been exhausted."""


@dataclass
class Tool:
    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Completion:
    text: str = ""
    reasoning: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    model_used: str = ""
    attempts: int = 0


def _parse_body(raw: str) -> dict:
    """Parse a 9router response body: one JSON object, or an SSE stream of
    deltas (see llm_body)."""
    return parse_completion_body(raw)


def _record_usage(model: str, usage: dict) -> None:
    if not usage:
        return
    if (p := usage.get("prompt_tokens")) is not None:
        llm_tokens_total.labels(service=_SERVICE, model=model, kind="prompt").inc(p)
    if (c := usage.get("completion_tokens")) is not None:
        llm_tokens_total.labels(service=_SERVICE, model=model, kind="completion").inc(c)


async def _resolve() -> tuple[str, str, str]:
    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    model = await get_setting("ninerouter_model", NINEROUTER_MODEL)
    base = NINEROUTER_BASE_URL.rstrip("/")
    return api_key, base, model


async def _resolve_chain(fallbacks: Iterable[str] | None) -> list[str]:
    _, _, primary = await _resolve()
    chain = [primary]
    for m in fallbacks or ():
        if m and m not in chain:
            chain.append(m)
    return chain


async def complete(
    messages: list[dict],
    *,
    model: str | None = None,
    fallbacks: Iterable[str] | None = None,
    temperature: float = 0.2,
    max_tokens: int = 2000,
    tools: list[Tool] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Completion:
    """Run a chat completion, walking the fallback chain until one succeeds."""
    api_key, base, _ = await _resolve()
    if not api_key:
        raise LLMError("no 9router API key configured")

    chain = [model] if model else await _resolve_chain(fallbacks)
    if model and fallbacks:
        for m in fallbacks:
            if m and m not in chain:
                chain.append(m)

    url = f"{base}/chat/completions"
    last_exc: Exception | None = None
    total_attempts = 0

    for idx, current_model in enumerate(chain):
        payload: dict[str, Any] = {
            "model": current_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters or {"type": "object", "properties": {}},
                    },
                }
                for t in tools
            ]

        for attempt in range(_MAX_ATTEMPTS):
            total_attempts += 1
            started = time.monotonic()
            try:
                async with _llm_semaphore:
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        resp = await client.post(
                            url,
                            headers={
                                "Authorization": f"Bearer {api_key}",
                                "Content-Type": "application/json",
                            },
                            json=payload,
                        )

                        if resp.status_code == 429:
                            retry_after = float(resp.headers.get("retry-after", 5.0))
                            wait = min(max(retry_after, 2.0), _MAX_RATE_LIMIT_WAIT)
                            llm_requests_total.labels(
                                service=_SERVICE, model=current_model, outcome="rate_limited"
                            ).inc()
                            log.warning(
                                "llm_rate_limited",
                                model=current_model,
                                attempt=attempt + 1,
                                wait_seconds=wait,
                            )
                            await asyncio.sleep(wait)
                            continue

                        resp.raise_for_status()
                        obj = _parse_body(resp.text)

                llm_latency_seconds.labels(service=_SERVICE, model=current_model).observe(
                    time.monotonic() - started
                )
                choice = obj["choices"][0]["message"]
                usage = obj.get("usage") or {}
                _record_usage(current_model, usage)
                llm_requests_total.labels(
                    service=_SERVICE, model=current_model, outcome="ok"
                ).inc()

                return Completion(
                    text=(choice.get("content") or "").strip(),
                    reasoning=(choice.get("reasoning_content") or "").strip(),
                    tool_calls=choice.get("tool_calls") or [],
                    usage=usage,
                    model_used=current_model,
                    attempts=total_attempts,
                )
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if exc.response.status_code >= 500:
                    if attempt == _MAX_ATTEMPTS - 1:
                        break
                    await asyncio.sleep(min(2.0 * (attempt + 1), _MAX_BACKOFF))
                    continue
                break
            except Exception as exc:
                last_exc = exc
                if attempt == _MAX_ATTEMPTS - 1:
                    break
                await asyncio.sleep(min(2.0 * (attempt + 1), _MAX_BACKOFF))

        llm_requests_total.labels(
            service=_SERVICE, model=current_model, outcome="error"
        ).inc()

        if idx + 1 < len(chain):
            nxt = chain[idx + 1]
            llm_fallbacks_total.labels(
                service=_SERVICE, from_model=current_model, to_model=nxt
            ).inc()
            log.warning("llm_fallback", **{"from": current_model, "to": nxt})

    raise LLMError(f"all models exhausted: {chain} (last: {last_exc})")


async def stream(
    messages: list[dict],
    *,
    model: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 2000,
    timeout: float = 120.0,
) -> AsyncIterator[dict]:
    """Yield chunks shaped like AI SDK stream events.

    Emits start / text-delta / reasoning-delta / finish / error so a Node layer
    can forward these verbatim if one is added later.
    """
    api_key, base, _ = await _resolve()
    if not api_key:
        yield {"type": "error", "message": "no 9router API key configured"}
        return

    current_model = model or (await _resolve())[2]
    url = f"{base}/chat/completions"
    payload = {
        "model": current_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": True,
    }

    yield {"type": "start", "model": current_model}

    try:
        async with _llm_semaphore:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                ) as resp:
                    resp.raise_for_status()
                    usage: dict[str, int] = {}
                    async for line in resp.aiter_lines():
                        line = (line or "").strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if not data or data == "[DONE]":
                            continue
                        try:
                            obj = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if obj.get("usage"):
                            usage = obj["usage"]
                        for choice in obj.get("choices") or []:
                            delta = choice.get("delta") or {}
                            if delta.get("content"):
                                yield {"type": "text-delta", "text": delta["content"]}
                            if delta.get("reasoning_content"):
                                yield {
                                    "type": "reasoning-delta",
                                    "text": delta["reasoning_content"],
                                }
                    _record_usage(current_model, usage)
                    llm_requests_total.labels(
                        service=_SERVICE, model=current_model, outcome="ok"
                    ).inc()
                    yield {"type": "finish", "usage": usage, "model": current_model}
    except Exception as exc:
        llm_requests_total.labels(
            service=_SERVICE, model=current_model, outcome="error"
        ).inc()
        log.warning("llm_stream_failed", model=current_model, error=str(exc))
        yield {"type": "error", "message": str(exc)}


def extract_json(text: str, schema: dict | None = None) -> dict | None:
    """Parse JSON out of a model reply, tolerating code fences.

    Returns None when the reply is not usable JSON, so callers keep their
    existing deterministic fallback instead of raising.
    """
    if not text:
        return None
    content = text.strip()
    if content.startswith("```"):
        parts = content.split("```")
        if len(parts) > 1:
            content = parts[1]
        if content.startswith("json"):
            content = content[4:]
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    if schema:
        required = schema.get("required") or []
        missing = [k for k in required if k not in parsed]
        if missing:
            log.warning("llm_schema_missing_fields", missing=missing)
            return None
    return parsed
