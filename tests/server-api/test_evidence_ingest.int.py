"""Durable receipt scenarios against a disposable PostgreSQL schema per test.

TEST_DATABASE_URL must explicitly name disposable PostgreSQL. No public schema resets.
"""
import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import ingest, system
from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import hash_token
from app.models import models
from app.schemas import schemas


@dataclass
class InboxEnvironment:
    sessions: async_sessionmaker
    agent_id: UUID
    token: str
    request: dict
    client: httpx.AsyncClient
    app: FastAPI

    async def accept(self, body=None):
        from app.services.evidence_inbox import accept_evidence
        async with self.sessions() as db:
            agent = await db.get(models.Agent, self.agent_id)
            return await accept_evidence(db, agent, schemas.EvidenceEnvelope.model_validate(
                self.request if body is None else body))

    async def post(self, body=None, token=None):
        return await self.client.post("/api/ingest/v2/log", json=self.request if body is None else body,
                                      headers={"X-Agent-Token": self.token if token is None else token})


@pytest.fixture
async def inbox_env(monkeypatch):
    assert hasattr(models, "EvidenceInbox"), "durable inbox model is not implemented"
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail("Set TEST_DATABASE_URL to a disposable PostgreSQL database")
    namespace = "evidence_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as db:
        await db.execute(text("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"))
        await db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_async_engine(
        url, connect_args={"server_settings": {"search_path": namespace}},
        execution_options={"schema_translate_map": {None: namespace}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.execute(text(f'SET LOCAL search_path TO "{namespace}", public'))
            await db.run_sync(Base.metadata.create_all)
        async with engine.connect() as db:
            for table in ("agents", "evidence_inbox", "evidence_group_usage"):
                actual_schema = await db.scalar(text("SELECT relnamespace::regnamespace::text FROM pg_class WHERE oid=to_regclass(:table)"), {"table": table})
                assert actual_schema == namespace, "fixture resolved a table outside its disposable schema"
        request = json.loads((Path(__file__).parents[1] / "fixtures/evidence-v2.json").read_text())
        schemas.EvidenceEnvelope.model_validate(request)
        agent_id, token = UUID(request["agent_id"]), "fixture-agent-token"
        async with sessions() as db:
            db.add(models.Agent(id=agent_id, name="Test Agent", hostname="server-host", group_id="original",
                                token_hash=hash_token(token), approved=True))
            await db.commit()
        app = FastAPI()
        app.include_router(ingest.router)
        app.include_router(system.router)

        async def database():
            async with sessions() as db:
                yield db

        app.dependency_overrides[get_db] = database
        monkeypatch.setattr(settings, "EVIDENCE_INGEST_ENABLED", True)
        monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", 1 << 30)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield InboxEnvironment(sessions, agent_id, token, request, client, app)
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()


async def test_committed_receipt_and_exact_payload_roundtrip(inbox_env):
    response = await inbox_env.post()
    assert response.status_code == 202, response.text
    receipt = response.json()
    assert receipt["protocol_version"] == 2 and receipt["status"] == "accepted"
    assert receipt["event_id"] == inbox_env.request["event_id"]
    async with inbox_env.sessions() as db:
        row = await db.get(models.EvidenceInbox, UUID(receipt["receipt_id"]))
        assert row is not None and row.status == "pending"
        assert row.hostname == "server-host" and row.group_id == "original"
        payload = json.loads(row.payload)
        assert payload == inbox_env.request
        assert payload["raw_message"] == "a\n\x00b 世界"
        assert payload["collected_at"].endswith(".123456789Z")
        assert row.payload_bytes == len(json.dumps(row.payload, ensure_ascii=False).encode())
        assert (await db.get(models.EvidenceGroupUsage, "original")).payload_bytes == row.payload_bytes
    second = inbox_env.request | {"event_id": str(uuid4()), "raw_message": r"a\n\u0000b 世界"}
    receipt2 = await inbox_env.accept(second)
    async with inbox_env.sessions() as db:
        row = await db.get(models.EvidenceInbox, receipt2.receipt_id)
        assert json.loads(row.payload)["raw_message"] == r"a\n\u0000b 世界"


async def test_eight_concurrent_http_retries_share_one_committed_receipt(inbox_env):
    responses = await asyncio.gather(*(inbox_env.post() for _ in range(8)))
    assert [r.status_code for r in responses] == [202] * 8
    bodies = [r.json() for r in responses]
    assert len({r["receipt_id"] for r in bodies}) == 1
    assert sorted(r["status"] for r in bodies) == ["accepted"] + ["duplicate"] * 7
    async with inbox_env.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(models.EvidenceInbox)) == 1
        row = (await db.execute(select(models.EvidenceInbox))).scalar_one()
        assert (await db.get(models.EvidenceGroupUsage, "original")).payload_bytes == row.payload_bytes


async def test_commit_failure_rolls_back_usage_and_never_returns_receipt(inbox_env, monkeypatch):
    from app.services.evidence_inbox import accept_evidence
    async with inbox_env.sessions() as db:
        agent = await db.get(models.Agent, inbox_env.agent_id)
        async def failed_commit():
            raise SQLAlchemyError("injected commit failure")
        monkeypatch.setattr(db, "commit", failed_commit)
        with pytest.raises(HTTPException) as exc:
            await accept_evidence(db, agent, schemas.EvidenceEnvelope.model_validate(inbox_env.request))
        assert exc.value.status_code == 503
        assert not db.in_transaction()
    async with inbox_env.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(models.EvidenceInbox)) == 0
        assert await db.scalar(select(func.count()).select_from(models.EvidenceGroupUsage)) == 0
    assert (await inbox_env.accept()).status == "accepted"


async def test_duplicate_at_full_quota_and_last_capacity_across_sessions(inbox_env, monkeypatch):
    first = await inbox_env.accept()
    async with inbox_env.sessions() as db:
        row = await db.get(models.EvidenceInbox, first.receipt_id)
        size = row.payload_bytes
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", size)
    assert (await inbox_env.accept()).receipt_id == first.receipt_id
    assert (await inbox_env.post(inbox_env.request | {"event_id": str(uuid4())})).status_code == 429
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", size * 2)
    results = await asyncio.gather(*(inbox_env.post(inbox_env.request | {"event_id": str(uuid4())}) for _ in range(8)))
    assert sorted(r.status_code for r in results) == [202] + [429] * 7
    async with inbox_env.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(models.EvidenceInbox)) == 2
        assert (await db.get(models.EvidenceGroupUsage, "original")).payload_bytes == size * 2


@pytest.mark.parametrize("change", [
    {"raw_message": "changed"}, {"collected_at": "2026-10-21T01:02:03.123456788Z"},
    {"hostname": "changed"}, {"legacy_import": True},
    {"cursor": {"source": "file", "generation": "one", "identity": "other", "offset": 42}},
])
async def test_immutable_change_is_conflict(inbox_env, change):
    await inbox_env.accept()
    assert (await inbox_env.post(inbox_env.request | change)).status_code == 409


async def test_group_move_and_agent_deletion_preserve_original_receipt(inbox_env, monkeypatch):
    first = await inbox_env.accept()
    async with inbox_env.sessions() as db:
        await db.execute(update(models.Agent).values(group_id="new", hostname="moved-host"))
        await db.commit()
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", 1)
    assert (await inbox_env.accept()).receipt_id == first.receipt_id
    async with inbox_env.sessions() as db:
        await db.execute(delete(models.Agent))
        await db.commit()
        row = await db.get(models.EvidenceInbox, first.receipt_id)
        assert row.agent_id == inbox_env.agent_id
        assert row.group_id == "original" and row.hostname == "server-host"


async def test_auth_identity_and_approval_require_real_database_agent(inbox_env):
    assert (await inbox_env.post(token="invalid")).status_code == 401
    assert (await inbox_env.client.post("/api/ingest/v2/log", json=inbox_env.request)).status_code == 401
    assert (await inbox_env.post(inbox_env.request | {"agent_id": str(uuid4())})).status_code == 403
    async with inbox_env.sessions() as db:
        await db.execute(update(models.Agent).values(approved=False))
        await db.commit()
    response = await inbox_env.post()
    assert response.status_code == 403 and response.json()["detail"] == "pending_approval"
    assert response.headers.get("Retry-After")


async def test_invalid_version_and_maximum_go_encoded_event(inbox_env):
    assert (await inbox_env.post(inbox_env.request | {"protocol_version": 3})).status_code == 422
    body = schemas.EvidenceEnvelope.model_validate(inbox_env.request | {"raw_message": ""})
    exact = inbox_env.request | {"raw_message": "x" * ((1 << 20) - body.encoded_size)}
    assert (await inbox_env.post(exact)).status_code == 202
    assert (await inbox_env.post(exact | {"raw_message": exact["raw_message"] + "x"})).status_code == 413
    assert (await inbox_env.post(inbox_env.request | {"raw_message": "<" * 200000})).status_code == 413


@pytest.mark.parametrize("content_length", [None, "1", str(3 << 20)])
async def test_request_bound_precedes_parsing_and_stops_reading_chunks(inbox_env, content_length):
    received = 0
    sent = []
    headers = [(b"x-agent-token", inbox_env.token.encode()), (b"content-type", b"application/json")]
    if content_length is not None:
        headers.append((b"content-length", content_length.encode()))
    async def receive():
        nonlocal received
        received += 1
        assert received <= 3, "bounded reader consumed the rest of an oversized request"
        return {"type": "http.request", "body": b"x" * (1 << 20), "more_body": True}
    async def send(message):
        sent.append(message)
    await inbox_env.app({"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                         "method": "POST", "scheme": "http", "path": "/api/ingest/v2/log",
                         "raw_path": b"/api/ingest/v2/log", "query_string": b"", "headers": headers,
                         "client": ("test", 1), "server": ("test", 80)}, receive, send)
    assert sent[0]["status"] == 413
    assert received == (0 if content_length == str(3 << 20) else 3)


@pytest.mark.parametrize("mode", ["disabled", "healthy", "missing", "unlogged", "unsafe", "unsafe_full_pages", "unavailable", "missing_unique", "missing_column"])
async def test_readiness_capability_and_acceptance_agree(inbox_env, monkeypatch, mode):
    from app.services import evidence_inbox
    if mode == "disabled":
        monkeypatch.setattr(settings, "EVIDENCE_INGEST_ENABLED", False)
    if mode == "missing":
        async with inbox_env.sessions() as db:
            await db.execute(text("DROP TABLE evidence_group_usage"))
            await db.commit()
    if mode == "unlogged":
        async with inbox_env.sessions() as db:
            await db.execute(text("ALTER TABLE evidence_inbox SET UNLOGGED"))
            await db.commit()
    if mode == "missing_unique":
        async with inbox_env.sessions() as db:
            await db.execute(text("ALTER TABLE evidence_inbox DROP CONSTRAINT uq_evidence_inbox_agent_event"))
            await db.commit()
    if mode == "missing_column":
        async with inbox_env.sessions() as db:
            await db.execute(text("ALTER TABLE evidence_inbox DROP COLUMN payload_digest"))
            await db.commit()
    if mode in {"unsafe", "unsafe_full_pages", "unavailable"}:
        execute = evidence_inbox.AsyncSession.execute
        async def simulate_setting(db, statement, *args, **kwargs):
            if str(statement) == ("SHOW full_page_writes" if mode == "unsafe_full_pages" else "SHOW fsync"):
                if mode == "unavailable":
                    raise SQLAlchemyError("setting unavailable")
                return await execute(db, text("SELECT 'off'"))
            return await execute(db, statement, *args, **kwargs)
        monkeypatch.setattr(evidence_inbox.AsyncSession, "execute", simulate_setting)
    ready = await inbox_env.client.get("/ready")
    heartbeat = await inbox_env.client.post("/api/ingest/heartbeat", json={
        "agent_id": str(inbox_env.agent_id), "version": "test"}, headers={"X-Agent-Token": inbox_env.token})
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["evidence_protocols"] == ([2] if mode == "healthy" else [])
    assert ready.status_code == (200 if mode in {"disabled", "healthy"} else 503)
    assert (await inbox_env.post()).status_code == (202 if mode == "healthy" else 503)


async def test_synchronous_commit_overrides_unsafe_session_default(inbox_env):
    from app.services.evidence_inbox import accept_evidence
    async with inbox_env.sessions() as db:
        await db.execute(text("""
            CREATE FUNCTION require_sync() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF current_setting('synchronous_commit') <> 'on' THEN
                    RAISE EXCEPTION 'acceptance must force synchronous_commit on';
                END IF;
                RETURN NEW;
            END $$
        """))
        await db.execute(text("CREATE TRIGGER require_sync BEFORE INSERT ON evidence_inbox FOR EACH ROW EXECUTE FUNCTION require_sync()"))
        await db.execute(text("SET synchronous_commit=off"))
        await db.commit()
        agent = await db.get(models.Agent, inbox_env.agent_id)
        receipt = await accept_evidence(db, agent, schemas.EvidenceEnvelope.model_validate(inbox_env.request))
        assert receipt.status == "accepted"
    async with inbox_env.sessions() as db:
        assert await db.get(models.EvidenceInbox, receipt.receipt_id) is not None


async def test_different_agents_compete_for_last_group_capacity(inbox_env, monkeypatch):
    original = await inbox_env.accept()
    async with inbox_env.sessions() as db:
        size = (await db.get(models.EvidenceInbox, original.receipt_id)).payload_bytes
        identities = [(uuid4(), f"token-{i}") for i in range(8)]
        for agent_id, token in identities:
            db.add(models.Agent(id=agent_id, name="Test", hostname="server-host", group_id="original",
                                token_hash=hash_token(token), approved=True))
        await db.commit()
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", size * 2)
    responses = await asyncio.gather(*(inbox_env.post(inbox_env.request | {
        "agent_id": str(agent_id), "event_id": str(uuid4())}, token=token) for agent_id, token in identities))
    assert sorted(r.status_code for r in responses) == [202] + [429] * 7
    async with inbox_env.sessions() as db:
        assert (await db.get(models.EvidenceGroupUsage, "original")).payload_bytes == size * 2
        assert await db.scalar(select(func.count()).select_from(models.EvidenceInbox)) == 2


async def test_stale_authenticated_snapshot_during_group_move(inbox_env):
    from app.services.evidence_inbox import accept_evidence
    async with inbox_env.sessions() as stale_db:
        stale_agent = await stale_db.get(models.Agent, inbox_env.agent_id)
        assert stale_agent.group_id == "original"
        async with inbox_env.sessions() as move_db:
            await move_db.execute(update(models.Agent).values(group_id="moved", hostname="new-host"))
            await move_db.commit()
        old, new = await asyncio.gather(
            accept_evidence(stale_db, stale_agent, schemas.EvidenceEnvelope.model_validate(inbox_env.request)),
            inbox_env.accept(),
        )
        assert old.receipt_id == new.receipt_id
    async with inbox_env.sessions() as db:
        row = await db.get(models.EvidenceInbox, old.receipt_id)
        assert row.group_id == "moved" and row.hostname == "new-host"
        assert await db.get(models.EvidenceGroupUsage, "original") is None
        assert (await db.get(models.EvidenceGroupUsage, "moved")).payload_bytes == row.payload_bytes


async def test_migration_creates_durable_schema_and_indexes_idempotently(inbox_env, monkeypatch):
    from app.services import evidence_schema
    from app.services.evidence_inbox import check_evidence_durability
    async with inbox_env.sessions() as db:
        await db.execute(text("DROP TABLE evidence_inbox, evidence_group_usage"))
        await db.commit()
        assert not await check_evidence_durability(db)
        monkeypatch.setattr(evidence_schema, "engine", db.bind)
        await db.execute(text("SELECT pg_advisory_lock(727501001)"))
        try:
            await evidence_schema.migrate_evidence()
            await evidence_schema.migrate_evidence()
        finally:
            await db.execute(text("SELECT pg_advisory_unlock(727501001)"))
        assert await check_evidence_durability(db)
        indexes = (await db.execute(text("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename='evidence_inbox'"))).scalars().all()
        assert {"idx_evidence_dispatch", "idx_evidence_attempt", "idx_evidence_retention"} <= set(indexes)
    assert (await inbox_env.accept()).status == "accepted"


@pytest.mark.parametrize("timestamp", ["0001-01-01T00:00:00+23:00", "9999-12-31T23:59:59-23:00"])
async def test_timestamp_utc_range_is_validation_error(inbox_env, timestamp):
    assert (await inbox_env.post(inbox_env.request | {"collected_at": timestamp})).status_code == 422
