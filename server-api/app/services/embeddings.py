# server-api/app/services/embeddings.py
"""Query embeddings for semantic search over the RAG index the worker builds
(worker/worker/rag.py). Same model, so vectors are comparable; baked into the
image (server-api/Dockerfile)."""
import asyncio
import os

import structlog

log = structlog.get_logger()

EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # must match worker/worker/rag.py
_embedder = None


def _embed_sync(text: str) -> list[float]:
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding(model_name=EMBED_MODEL, cache_dir=os.environ.get("FASTEMBED_CACHE_PATH"))
    return list(_embedder.embed([text]))[0].tolist()


async def embed(text: str) -> list[float] | None:
    """The query's vector, or None when the model can't be loaded (callers
    fall back to keyword search)."""
    try:
        return await asyncio.to_thread(_embed_sync, text)
    except Exception as exc:  # noqa: BLE001 — search must still answer
        log.warning("embed_failed", error=str(exc))
        return None
