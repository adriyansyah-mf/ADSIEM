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
