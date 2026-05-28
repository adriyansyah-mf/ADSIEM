"""RAG — embed resolved cases and retrieve similar ones at triage time."""
from __future__ import annotations
import uuid
from typing import Optional

import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal

log = structlog.get_logger()

_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
    return _embedder


def embed_text(text: str) -> list[float]:
    """Return 384-dim embedding vector for text."""
    embedder = _get_embedder()
    vectors = list(embedder.embed([text]))
    return vectors[0].tolist()


async def index_case(
    case_id: str,
    title: str,
    description: Optional[str],
    verdict: str,
    group_id: str,
) -> None:
    """Embed a resolved case and upsert into case_embeddings."""
    summary = f"{title}\n{description or ''}\nVerdict: {verdict}".strip()
    try:
        vector = embed_text(summary)
    except Exception as e:
        log.warning("rag_embed_failed", case_id=case_id, error=str(e))
        return

    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                INSERT INTO case_embeddings (id, case_id, group_id, embedding, summary_text)
                VALUES (:id, :case_id, :group_id, :embedding, :summary_text)
                ON CONFLICT (case_id) DO UPDATE
                    SET embedding = EXCLUDED.embedding,
                        summary_text = EXCLUDED.summary_text
            """), {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "group_id": group_id,
                "embedding": str(vector),
                "summary_text": summary,
            })
            await db.commit()
        log.info("rag_case_indexed", case_id=case_id)
    except Exception as e:
        log.warning("rag_index_failed", case_id=case_id, error=str(e))


async def retrieve_similar_cases(
    query_text: str,
    group_id: str,
    top_k: int = 3,
    min_score: float = 0.60,
) -> list[dict]:
    """
    Return top-k resolved/closed cases most similar to query_text.
    Each result: {title, description, verdict, similarity, case_id}
    """
    try:
        vector = embed_text(query_text)
    except Exception as e:
        log.warning("rag_embed_query_failed", error=str(e))
        return []

    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    c.id::text                                           AS case_id,
                    c.title,
                    c.description,
                    c.status,
                    1 - (ce.embedding <=> :embedding::vector)           AS similarity
                FROM case_embeddings ce
                JOIN cases c ON c.id = ce.case_id
                WHERE ce.group_id = :group_id
                  AND c.status IN ('resolved', 'closed')
                  AND 1 - (ce.embedding <=> :embedding::vector) >= :min_score
                ORDER BY ce.embedding <=> :embedding::vector
                LIMIT :top_k
            """), {
                "embedding": str(vector),
                "group_id": group_id,
                "min_score": min_score,
                "top_k": top_k,
            })).mappings().all()
            return [dict(r) for r in rows]
    except Exception as e:
        log.warning("rag_retrieve_failed", error=str(e))
        return []
