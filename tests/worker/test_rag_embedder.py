# tests/worker/test_rag_embedder.py
"""Without the embedding model (not baked, HuggingFace unreachable) RAG must
fail fast instead of retrying a slow download on every alert."""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker import rag  # noqa: E402


def test_a_failed_model_load_is_not_retried_on_every_call(monkeypatch):
    attempts = []

    class Unreachable:
        def __init__(self, **kwargs):
            attempts.append(kwargs)
            raise ValueError("Could not load model BAAI/bge-small-en-v1.5 from any source.")

    monkeypatch.setitem(sys.modules, "fastembed", types.SimpleNamespace(TextEmbedding=Unreachable))
    monkeypatch.setattr(rag, "_embedder", None)
    monkeypatch.setattr(rag, "_failed_at", 0.0)

    with pytest.raises(ValueError):
        rag.embed_text("first alert")
    with pytest.raises(RuntimeError, match="retrying later"):
        rag.embed_text("second alert")
    assert len(attempts) == 1

    monkeypatch.setattr(rag, "_failed_at", rag._failed_at - rag.EMBED_RETRY_SECONDS - 1)
    with pytest.raises(ValueError):
        rag.embed_text("after the back-off")
    assert len(attempts) == 2
