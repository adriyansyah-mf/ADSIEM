# tests/server-api/test_sop_search.int.py
"""search_sop (assistant + AI investigator): semantic search over the SOP
chunks the worker indexes, keyword fallback without the embedding model.
A fake embedder keeps this offline.

Needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector."""
import asyncio
import os
import uuid

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()
TOPICS = ["ransomware", "phishing", "brute force"]


def _run(coro):
    return _LOOP.run_until_complete(coro)


def _vec(text):
    """One axis per topic: texts about the same topic are close."""
    v = [0.0] * 384
    for i, topic in enumerate(TOPICS):
        if topic in text.lower():
            v[i] = 1.0
    v[383] = 0.01
    return v


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
            # added by main.py at startup, not by the ORM model
            await conn.execute(text("ALTER TABLE sop_chunks ADD COLUMN IF NOT EXISTS embedding vector(384)"))
    _run(setup())
    _run(_seed())
    yield
    _run(engine.dispose())


async def _seed():
    from sqlalchemy import text

    from app.core.database import AsyncSessionLocal
    from app.models.models import SopDocument

    docs = [("ir-ransomware.md", "blue", "Ransomware: isolate the host first, then preserve memory."),
            ("ir-phishing.md", "blue", "Phishing: pull the mail from every inbox and reset the user's password."),
            ("other-group.md", "red", "Ransomware: red team's own procedure.")]
    async with AsyncSessionLocal() as db:
        for filename, group, chunk in docs:
            doc = SopDocument(filename=filename, group_id=group, raw_text=chunk, status="indexed")
            db.add(doc)
            await db.flush()
            await db.execute(text(
                "INSERT INTO sop_chunks (id, document_id, group_id, chunk_index, chunk_text, embedding) "
                "VALUES (:id, :doc, :g, 0, :t, CAST(:e AS vector))"),
                {"id": str(uuid.uuid4()), "doc": doc.id, "g": group, "t": chunk, "e": str(_vec(chunk))})
        await db.commit()


def _search(monkeypatch, query, group, embedder):
    from app.core.database import AsyncSessionLocal
    from app.services import assistant_tools, embeddings

    monkeypatch.setattr(embeddings, "embed", embedder)

    async def go():
        async with AsyncSessionLocal() as db:
            return await assistant_tools.run_tool("search_sop", {"query": query, "limit": 2}, db, group)
    return _run(go())


def test_semantic_search_returns_the_relevant_passage_of_the_group(env, monkeypatch):
    async def fake_embed(text):
        return _vec(text)

    out = _search(monkeypatch, "what do we do about ransomware on a server?", "blue", fake_embed)
    assert out["mode"] == "semantic"
    assert out["passages"][0]["filename"] == "ir-ransomware.md"
    assert "isolate the host first" in out["passages"][0]["text"]
    assert all(p["filename"] != "other-group.md" for p in out["passages"])  # group scoped


def test_keyword_fallback_without_the_model(env, monkeypatch):
    async def no_model(text):
        return None

    out = _search(monkeypatch, "reset the user", "blue", no_model)
    assert out["mode"] == "keyword"
    assert [p["filename"] for p in out["passages"]] == ["ir-phishing.md"]
