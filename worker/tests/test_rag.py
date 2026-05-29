# worker/tests/test_rag.py
import pytest

def test_case_embedding_model_has_required_fields():
    from worker.models import CaseEmbedding
    cols = {c.name for c in CaseEmbedding.__table__.columns}
    assert "case_id" in cols
    assert "group_id" in cols
    assert "embedding" in cols
    assert "summary_text" in cols


def test_embed_text_returns_384_dimensions():
    from worker.rag import embed_text
    vec = embed_text("SSH brute force attack detected from 1.2.3.4")
    assert isinstance(vec, list)
    assert len(vec) == 384
    assert all(isinstance(v, float) for v in vec)


def test_embed_text_different_inputs_differ():
    from worker.rag import embed_text
    v1 = embed_text("SSH brute force")
    v2 = embed_text("DNS exfiltration via TXT records")
    assert v1 != v2


def test_retrieve_similar_cases_returns_list():
    from unittest.mock import AsyncMock, patch, MagicMock
    import asyncio

    async def run():
        with patch("worker.rag.AsyncSessionLocal") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_result = MagicMock()
            mock_result.mappings.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session_cls.return_value = mock_session

            from worker.rag import retrieve_similar_cases
            result = await retrieve_similar_cases("SSH brute force", "default")
            assert isinstance(result, list)

    asyncio.run(run())


def test_rag_indexer_module_importable():
    from worker.rag_indexer import rag_index_loop
    import asyncio
    assert asyncio.iscoroutinefunction(rag_index_loop)


def test_analyze_alert_accepts_similar_cases_param():
    import inspect
    from worker.groq_client import analyze_alert_with_groq
    sig = inspect.signature(analyze_alert_with_groq)
    assert "similar_cases" in sig.parameters


def test_sop_models_have_required_fields():
    from worker.models import SopDocument, SopChunk
    doc_cols = {c.name for c in SopDocument.__table__.columns}
    assert {"group_id", "filename", "raw_text", "status"}.issubset(doc_cols)
    chunk_cols = {c.name for c in SopChunk.__table__.columns}
    assert {"document_id", "group_id", "chunk_index", "chunk_text", "embedding"}.issubset(chunk_cols)


def test_chunk_text_splits_correctly():
    from worker.rag import _chunk_text
    text = "Paragraph one.\n\nParagraph two.\n\nParagraph three."
    chunks = _chunk_text(text, max_chars=30)
    assert len(chunks) >= 2
    assert all(len(c) <= 30 for c in chunks)
    assert all(c.strip() for c in chunks)


def test_retrieve_sop_context_returns_list():
    from unittest.mock import AsyncMock, patch, MagicMock
    import asyncio

    async def run():
        with patch("worker.rag.AsyncSessionLocal") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_result = MagicMock()
            mock_result.mappings.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session_cls.return_value = mock_session

            from worker.rag import retrieve_sop_context
            result = await retrieve_sop_context("brute force incident response", "default")
            assert isinstance(result, list)

    asyncio.run(run())
