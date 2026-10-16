# server-api/app/core/llm_client.py
"""Legacy shims over the shared LLM gateway.

Transport (retry, 429 backoff, SSE-quirk parsing, usage accounting) lives in
app/core/llm_gateway.py. These thin adapters preserve the old
generate_text()/generate_chat() signatures for the report-narrative and
assistant callers while routing every call through the gateway, so server-api
has one retry/fallback policy instead of two.

Both functions require a DB session because the gateway resolves the 9router
API key and model from the PlatformSetting table (not from env/cache).
"""
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.llm_gateway import LLMError, complete

log = structlog.get_logger()


async def generate_text(
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int = 1500,
    *,
    db: AsyncSession | None = None,
) -> str:
    """Single-turn completion. Returns "" on failure — callers treat that as
    "no AI narrative available", not an error."""
    return await generate_chat(
        api_key,
        model,
        [{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        db=db,
    )


async def generate_chat(
    api_key: str,
    model: str,
    messages: list[dict],
    max_tokens: int = 1200,
    *,
    db: AsyncSession | None = None,
) -> str:
    """Multi-turn completion. Returns "" on any failure, same contract as before."""
    if not api_key or db is None:
        return ""
    try:
        completion = await complete(
            db, messages, model=model, temperature=0.2, max_tokens=max_tokens
        )
        return completion.text
    except LLMError as exc:
        log.warning("llm_gateway_call_failed", error=str(exc))
        return ""
