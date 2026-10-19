# tests/worker/test_knowledge.int.py
"""Knowledge base against a real Postgres (pgvector): exact scope matches,
semantic matches with a fake embedder, indexing, the PayloadsAllTheThings sync
upsert, and the feedback backfill.

Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import io
import os
import sys
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()
TOPICS = ["scanner", "sql", "backup"]

# the server creates these (models.KnowledgeEntry, main._migrate_knowledge, RAG tables)
SCHEMA = [
    """CREATE TABLE knowledge_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), group_id VARCHAR(100) NOT NULL DEFAULT 'default',
        kind VARCHAR(20) NOT NULL DEFAULT 'note', source VARCHAR(50) NOT NULL DEFAULT 'analyst', source_ref TEXT,
        title VARCHAR(300) NOT NULL, content TEXT NOT NULL, scope JSONB NOT NULL DEFAULT '{}'::jsonb,
        enabled BOOLEAN NOT NULL DEFAULT true, expires_at TIMESTAMPTZ, created_by UUID,
        created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(), indexed_at TIMESTAMPTZ)""",
    """CREATE TABLE knowledge_chunks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        entry_id UUID NOT NULL REFERENCES knowledge_entries(id) ON DELETE CASCADE,
        group_id VARCHAR(100) NOT NULL DEFAULT 'default', kind VARCHAR(20) NOT NULL, chunk_index INTEGER NOT NULL,
        chunk_text TEXT NOT NULL, embedding vector(384) NOT NULL)""",
    "CREATE INDEX ON knowledge_chunks USING hnsw (embedding vector_cosine_ops)",
    """CREATE TABLE ai_feedback (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), entity_type VARCHAR(20) NOT NULL, entity_id UUID NOT NULL,
        context_text TEXT NOT NULL, ai_verdict VARCHAR(50), rating VARCHAR(20) NOT NULL, correct_verdict VARCHAR(50),
        note TEXT, group_id VARCHAR(100) NOT NULL DEFAULT 'default', created_by UUID, created_at TIMESTAMPTZ DEFAULT now())""",
    """CREATE TABLE feedback_embeddings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), feedback_id UUID NOT NULL REFERENCES ai_feedback(id) ON DELETE CASCADE,
        group_id VARCHAR(100) NOT NULL DEFAULT 'default', embedding vector(384) NOT NULL, rating VARCHAR(20) NOT NULL,
        summary_text TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE (feedback_id))""",
]


def _run(coro):
    return _LOOP.run_until_complete(coro)


def _vec(text):
    v = [0.0] * 384
    for i, topic in enumerate(TOPICS):
        if topic in text.lower():
            v[i] = 1.0
    v[383] = 0.01
    return v


@pytest.fixture()
def db(monkeypatch):
    from sqlalchemy import text

    from worker import knowledge, rag
    from worker.database import engine
    from worker.models import Base

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
            for stmt in SCHEMA:
                await conn.execute(text(stmt))
    _run(setup())
    monkeypatch.setattr(knowledge, "embed_texts", lambda texts: [_vec(t) for t in texts])
    monkeypatch.setattr(rag, "embed_text", _vec)

    async def embed(t):
        return _vec(t)
    monkeypatch.setattr(knowledge, "embed_or_none", embed)
    yield
    _run(engine.dispose())


def _sql(stmt, **params):
    from sqlalchemy import text

    from worker.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as s:
            res = await s.execute(text(stmt), params)
            await s.commit()
            try:
                return res.mappings().all()
            except Exception:  # noqa: BLE001 — statements without rows
                return None
    return _run(go())


def _note(title, content, scope="{}", group="blue", **extra):
    cols = ", ".join(["title", "content", "scope", "group_id", *extra])
    vals = ", ".join([":title", ":content", "CAST(:scope AS jsonb)", ":group_id", *(f":{k}" for k in extra)])
    return _sql(f"INSERT INTO knowledge_entries ({cols}) VALUES ({vals}) RETURNING id::text AS id",
                title=title, content=content, scope=scope, group_id=group, **extra)[0]["id"]


def test_exact_scope_semantic_expiry_and_groups(db):
    from worker import knowledge

    nessus = _note("10.20.0.5 is our Nessus scanner", "Weekly vulnerability scanner, Mondays 01:00.",
                   scope='{"ips": ["10.20.0.5"], "hosts": [], "users": [], "rules": []}')
    _note("Old scanner", "Retired scanner", scope='{"ips": ["10.20.0.5"]}', expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    _note("Other team's scanner", "red group scanner", scope='{"ips": ["10.20.0.5"]}', group="red")
    backup = _note("Nightly backup job", "The backup job uploads dumps to S3 at 02:00 with curl.")
    _sql("INSERT INTO knowledge_entries (group_id, kind, source, title, content) VALUES "
         "('*', 'reference', 'payloadsallthethings', 'SQL Injection — Union Based', 'UNION SELECT sql payloads')")
    while _run(knowledge.index_pending()):
        pass
    assert _sql("SELECT count(*) AS n FROM knowledge_entries WHERE indexed_at IS NULL")[0]["n"] == 0

    # exact: the scanner's IP, nothing about it in the title
    found = _run(knowledge.retrieve_for_alert("Nmap Port Scan Detected", "10.20.0.5", "web01", {}, "blue"))
    assert [n["id"] for n in found["notes"]][0] == nessus and found["notes"][0]["matched"] == ["ip 10.20.0.5"]
    assert all(n["title"] not in ("Old scanner", "Other team's scanner") for n in found["notes"])
    assert found["references"] == []  # not a web alert

    # semantic: no entity in common, same topic
    found = _run(knowledge.retrieve_for_alert("Outbound curl to S3 during backup window", None, "db01", {}, "blue"))
    assert backup in [n["id"] for n in found["notes"]]

    # web alert: payload reference too, shared across groups
    found = _run(knowledge.retrieve_for_alert("SQL Injection Attempt", "80.94.92.27", "web01",
                                              {"url.query": "q=1 union select"}, "blue"))
    assert [r["title"] for r in found["references"]] == ["SQL Injection — Union Based"]


def test_payloadsallthethings_sync_upserts_only_changes(db, monkeypatch):
    import httpx

    from worker import knowledge

    def archive(sections):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            md = "# X\n\n" + "\n\n".join(f"## {h}\n\n```\n{body}\n```" for h, body in sections.items())
            zf.writestr("PayloadsAllTheThings-master/SQL Injection/README.md", md)
        return buf.getvalue()

    payload = {"data": archive({"Union Based": "' UNION SELECT 1--", "Error Based": "AND extractvalue(1,1)"})}
    real = httpx.AsyncClient

    def client(**kw):
        return real(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=payload["data"])), **kw)
    monkeypatch.setattr(httpx, "AsyncClient", client)

    class Redis:
        def __init__(self):
            self.h = {}

        async def hset(self, key, mapping):
            self.h.update(mapping)

    redis = Redis()
    assert _run(knowledge.sync_payloadsallthethings(redis, "http://mirror/pat.zip")) == {
        "added": 2, "updated": 0, "removed": 0, "unchanged": 0}
    assert redis.h["status"] == "ok" and redis.h["entries"] == "2"
    while _run(knowledge.index_pending()):
        pass

    payload["data"] = archive({"Union Based": "' UNION SELECT 2--", "Time Based": "SLEEP(5)"})
    assert _run(knowledge.sync_payloadsallthethings(redis, "http://mirror/pat.zip")) == {
        "added": 1, "updated": 1, "removed": 1, "unchanged": 0}
    rows = _sql("SELECT title, indexed_at IS NULL OR indexed_at < updated_at AS stale FROM knowledge_entries ORDER BY title")
    assert [(r["title"], r["stale"]) for r in rows] == [
        ("SQL Injection — Time Based", True), ("SQL Injection — Union Based", True)]


def test_feedback_that_never_got_embedded_is_backfilled(db):
    from worker.rag_indexer import backfill_feedback

    _sql("INSERT INTO ai_feedback (entity_type, entity_id, context_text, ai_verdict, rating, correct_verdict) "
         "VALUES ('case', gen_random_uuid(), 'Nmap scan from 10.20.0.5', 'create_case', 'incorrect', 'false_positive')")
    assert _run(backfill_feedback()) == 1
    assert _sql("SELECT count(*) AS n FROM feedback_embeddings")[0]["n"] == 1
    assert _run(backfill_feedback()) == 0
