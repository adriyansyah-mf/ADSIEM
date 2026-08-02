# server-api/app/core/llm_client.py
"""Minimal 9router client for on-demand text generation from server-api
(PDF report narrative, SOC chat assistant) — the full AI analyst pipeline
(triage, hunts, campaigns) lives in worker/worker/llm_client.py; this is
intentionally a small, separate client since server-api and worker are
different services/containers."""
import asyncio
import json
import httpx
import structlog
from app.core.config import settings

log = structlog.get_logger()

_MAX_RETRIES = 3
_MAX_RATE_LIMIT_WAIT = 20.0


async def _post_chat(api_key: str, payload: dict) -> str:
    """POST a chat completion to 9router, retrying on 429/empty/transient
    failures — the free-tier "combo" model is flaky under load, same as the
    worker's AI analyst path (see worker/worker/llm_client.py::_llm_post)."""
    if not api_key:
        return ""
    url = f"{settings.NINEROUTER_BASE_URL.rstrip('/')}/chat/completions"
    delay = 3.0
    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                if resp.status_code == 429:
                    wait = min(max(float(resp.headers.get("retry-after", delay)), delay), _MAX_RATE_LIMIT_WAIT)
                    log.warning("ninerouter_rate_limited", attempt=attempt + 1, wait_seconds=wait)
                    await asyncio.sleep(wait)
                    delay = min(delay * 2, 30)
                    continue
                resp.raise_for_status()
                if not resp.text.strip():
                    raise ValueError("empty response body")
                # 9router replies with a text/event-stream body even for non-streaming
                # requests — a JSON object immediately followed by a trailing
                # "data: [DONE]" marker with no separator.
                obj, _ = json.JSONDecoder().raw_decode(resp.text)
                return obj["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            if attempt == _MAX_RETRIES - 1:
                log.warning("ninerouter_call_failed", error=str(exc))
                return ""
            log.warning("ninerouter_retry", attempt=attempt + 1, error=str(exc))
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
    return ""


async def generate_text(api_key: str, model: str, prompt: str, max_tokens: int = 1500) -> str:
    """POST a single-turn completion to 9router. Returns "" on any failure —
    callers should treat that as "no AI narrative available", not an error."""
    return await _post_chat(api_key, {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    })


async def generate_chat(api_key: str, model: str, messages: list[dict], max_tokens: int = 1200) -> str:
    """Multi-turn variant of generate_text — takes a full messages list
    (system/user/assistant) instead of a single prompt. Returns "" on any
    failure, same contract as generate_text."""
    return await _post_chat(api_key, {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": max_tokens,
    })
