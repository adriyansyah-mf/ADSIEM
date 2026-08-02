# server-api/app/core/llm_client.py
"""Minimal 9router client for on-demand text generation from server-api
(currently just the PDF report narrative) — the full AI analyst pipeline
(triage, hunts, campaigns) lives in worker/worker/llm_client.py; this is
intentionally a small, separate client since server-api and worker are
different services/containers."""
import json
import httpx
import structlog
from app.core.config import settings

log = structlog.get_logger()


async def generate_text(api_key: str, model: str, prompt: str, max_tokens: int = 1500) -> str:
    """POST a single-turn completion to 9router. Returns "" on any failure —
    callers should treat that as "no AI narrative available", not an error."""
    if not api_key:
        return ""
    url = f"{settings.NINEROUTER_BASE_URL.rstrip('/')}/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
            # 9router replies with a text/event-stream body even for non-streaming
            # requests — a JSON object immediately followed by a trailing
            # "data: [DONE]" marker with no separator (see worker/worker/llm_client.py).
            obj, _ = json.JSONDecoder().raw_decode(resp.text)
            return obj["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.warning("report_narrative_failed", error=str(exc))
        return ""


async def generate_chat(api_key: str, model: str, messages: list[dict], max_tokens: int = 1200) -> str:
    """Multi-turn variant of generate_text — takes a full messages list
    (system/user/assistant) instead of a single prompt. Returns "" on any
    failure, same contract as generate_text."""
    if not api_key:
        return ""
    url = f"{settings.NINEROUTER_BASE_URL.rstrip('/')}/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0.2,
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
            obj, _ = json.JSONDecoder().raw_decode(resp.text)
            return obj["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.warning("assistant_chat_failed", error=str(exc))
        return ""
