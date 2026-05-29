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


def _chunk_text(text: str, max_chars: int = 800) -> list[str]:
    """Split text into chunks at paragraph boundaries, max max_chars each."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 <= max_chars:
            current = f"{current}\n\n{para}".strip()
        else:
            if current:
                chunks.append(current)
            # if single paragraph exceeds max, split by sentence roughly
            if len(para) > max_chars:
                for i in range(0, len(para), max_chars):
                    chunks.append(para[i:i + max_chars])
            else:
                current = para
    if current:
        chunks.append(current)
    return chunks


async def index_sop_document(document_id: str, group_id: str, raw_text: str) -> None:
    """Chunk and embed a SOP document, insert into sop_chunks, mark document indexed."""
    chunks = _chunk_text(raw_text)
    if not chunks:
        log.warning("sop_empty_document", document_id=document_id)
        return

    rows = []
    for i, chunk in enumerate(chunks):
        try:
            vector = embed_text(chunk)
        except Exception as e:
            log.warning("sop_embed_chunk_failed", document_id=document_id, chunk=i, error=str(e))
            continue
        rows.append({
            "id": str(uuid.uuid4()),
            "document_id": document_id,
            "group_id": group_id,
            "chunk_index": i,
            "chunk_text": chunk,
            "embedding": str(vector),
        })

    try:
        async with AsyncSessionLocal() as db:
            for row in rows:
                await db.execute(text("""
                    INSERT INTO sop_chunks
                        (id, document_id, group_id, chunk_index, chunk_text, embedding)
                    VALUES
                        (:id, :document_id, :group_id, :chunk_index, :chunk_text, :embedding)
                    ON CONFLICT DO NOTHING
                """), row)
            await db.execute(text("""
                UPDATE sop_documents SET status = 'indexed', updated_at = now()
                WHERE id = :id
            """), {"id": document_id})
            await db.commit()
        log.info("sop_document_indexed", document_id=document_id, chunks=len(rows))
    except Exception as e:
        log.warning("sop_index_failed", document_id=document_id, error=str(e))
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                UPDATE sop_documents SET status = 'failed', updated_at = now()
                WHERE id = :id
            """), {"id": document_id})
            await db.commit()


async def retrieve_sop_context(
    query_text: str,
    group_id: str,
    top_k: int = 3,
    min_score: float = 0.55,
) -> list[str]:
    """
    Return top-k SOP chunk texts most relevant to query_text.
    Returns plain strings — injected directly into the prompt.
    """
    try:
        vector = embed_text(query_text)
    except Exception as e:
        log.warning("sop_embed_query_failed", error=str(e))
        return []

    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    sc.chunk_text,
                    sd.filename,
                    1 - (sc.embedding <=> :embedding::vector) AS similarity
                FROM sop_chunks sc
                JOIN sop_documents sd ON sd.id = sc.document_id
                WHERE sc.group_id = :group_id
                  AND sd.status = 'indexed'
                  AND 1 - (sc.embedding <=> :embedding::vector) >= :min_score
                ORDER BY sc.embedding <=> :embedding::vector
                LIMIT :top_k
            """), {
                "embedding": str(vector),
                "group_id": group_id,
                "min_score": min_score,
                "top_k": top_k,
            })).mappings().all()
            return [f"[{r['filename']}] {r['chunk_text']}" for r in rows]
    except Exception as e:
        log.warning("sop_retrieve_failed", error=str(e))
        return []
