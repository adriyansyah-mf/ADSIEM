# server-api/app/services/embeddings.py
"""Query embeddings for semantic search over the RAG index the worker builds
(worker/worker/rag.py). Same model, so vectors are comparable; baked into the
image (server-api/Dockerfile)."""
import asyncio
import os
import time

import structlog

log = structlog.get_logger()

EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # must match worker/worker/rag.py
_embedder = None


EMBED_RETRY_SECONDS = 600  # after a failed load, keyword search until then instead of a slow retry
_failed_at = 0.0


def _embed_sync(text: str) -> list[float]:
    global _embedder, _failed_at
    if _embedder is None:
        if _failed_at and time.monotonic() - _failed_at < EMBED_RETRY_SECONDS:
            raise RuntimeError("embedding model unavailable; retrying later")
        from fastembed import TextEmbedding
        try:
            _embedder = TextEmbedding(model_name=EMBED_MODEL, cache_dir=os.environ.get("FASTEMBED_CACHE_PATH"))
        except Exception:
            _failed_at = time.monotonic()
            raise
    return list(_embedder.embed([text]))[0].tolist()


async def embed(text: str) -> list[float] | None:
    """The query's vector, or None when the model can't be loaded (callers
    fall back to keyword search)."""
    try:
        return await asyncio.to_thread(_embed_sync, text)
    except Exception as exc:  # noqa: BLE001 — search must still answer
        log.warning("embed_failed", error=str(exc))
        return None
