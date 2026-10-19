# tests/server-api/test_knowledge_api.int.py
"""Knowledge API: notes are stored with normalised scopes, matched exactly in the
preview (and so in triage), disabled/deleted notes stop matching, and the
learned list says which feedback the AI has. Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    from app.main import _migrate_knowledge
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("""CREATE TABLE feedback_embeddings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), feedback_id UUID NOT NULL REFERENCES ai_feedback(id),
                group_id VARCHAR(100) NOT NULL DEFAULT 'default', embedding vector(384) NOT NULL,
                rating VARCHAR(20) NOT NULL, summary_text TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())"""))
        await _migrate_knowledge()
    _run(setup())
    yield
    _run(engine.dispose())


USER = SimpleNamespace(id=None, group_id="blue")


def _call(fn, *args, **kwargs):
    from app.core.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as db:
            return await fn(*args, db=db, **kwargs)
    return _run(go())


async def _no_model(text):
    return None


def test_notes_match_exactly_until_disabled_or_deleted(env, monkeypatch):
    from app.api.routes import knowledge as k
    from app.services import embeddings

    monkeypatch.setattr(embeddings, "embed", _no_model)  # exact matching must work without the model
    body = k.NoteIn(title="10.20.0.5 is our Nessus scanner", content="Scans every Monday at 01:00.",
                    scope=k.Scope(ips=[" 10.20.0.5 "], hosts=["NESSUS01"]))
    note = _call(k.create_note, body, BackgroundTasks(), user=USER, group_filter="blue")
    assert note.scope == {"ips": ["10.20.0.5"], "hosts": ["nessus01"], "users": [], "rules": []}
    assert note.group_id == "blue" and not note.indexed

    preview = _call(k.preview, k.PreviewIn(text="Nmap Port Scan from 10.20.0.5"), _=USER, group_filter="blue")
    assert [n["title"] for n in preview["notes"]] == [body.title] and preview["semantic"] is False
    assert preview["notes"][0]["matched"] == ["ip 10.20.0.5"]
    other_group = _call(k.preview, k.PreviewIn(text="scan from 10.20.0.5"), _=USER, group_filter="red")
    assert other_group["notes"] == []

    body.enabled = False
    _call(k.update_note, note.id, body, BackgroundTasks(), user=USER, group_filter="blue")
    assert _call(k.preview, k.PreviewIn(text="scan from 10.20.0.5"), _=USER, group_filter="blue")["notes"] == []

    _call(k.delete_note, note.id, BackgroundTasks(), user=USER, group_filter="blue")
    with pytest.raises(HTTPException) as exc:
        _call(k.delete_note, note.id, BackgroundTasks(), user=USER, group_filter="blue")
    assert exc.value.status_code == 404


def test_learned_says_which_feedback_the_ai_has(env):
    from sqlalchemy import text

    from app.api.routes import knowledge as k
    from app.core.database import AsyncSessionLocal
    from app.models.models import AiFeedback

    async def seed():
        async with AsyncSessionLocal() as db:
            a = AiFeedback(entity_type="case", entity_id=uuid.uuid4(), context_text="Nmap scan from 10.20.0.5",
                           ai_verdict="create_case", rating="incorrect", correct_verdict="false_positive",
                           note="our scanner", group_id="blue")
            b = AiFeedback(entity_type="alert", entity_id=uuid.uuid4(), context_text="SQLi on /login",
                           ai_verdict="create_case", rating="correct", group_id="blue")
            db.add_all([a, b])
            await db.flush()
            await db.execute(text("INSERT INTO feedback_embeddings (feedback_id, group_id, embedding, rating, "
                                  "summary_text) VALUES (:f, 'blue', CAST(:v AS vector), 'incorrect', 'x')"),
                             {"f": a.id, "v": str([0.0] * 383 + [1.0])})
            await db.commit()
    _run(seed())
    items = _call(k.learned, _=USER, group_filter="blue")["items"]
    assert {(i["context"], i["in_ai_memory"]) for i in items} == {
        ("Nmap scan from 10.20.0.5", True), ("SQLi on /login", False)}
