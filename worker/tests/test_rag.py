# worker/tests/test_rag.py
import pytest

def test_case_embedding_model_has_required_fields():
    from worker.models import CaseEmbedding
    cols = {c.name for c in CaseEmbedding.__table__.columns}
    assert "case_id" in cols
    assert "group_id" in cols
    assert "embedding" in cols
    assert "summary_text" in cols
