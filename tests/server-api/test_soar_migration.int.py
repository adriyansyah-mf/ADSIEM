# tests/server-api/test_soar_migration.int.py
"""Startup migration on a database that already has the soar-v2 branch's
soar_runs / soar_run_steps tables (a different schema, deployed from
feature/soar-engine-core). Those were silently kept by CREATE TABLE IF NOT
EXISTS and the next index on updated_at failed, so server-api never started.
Playbook runs now live in their own tables and the v2 ones are left alone.
Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import os

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()

# Shape created by feature/soar-engine-core (trimmed to what matters here).
V2_TABLES = [
    """CREATE TABLE soar_runs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workflow_id UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending', trigger_type VARCHAR(30) NOT NULL,
        trigger_ref JSONB NOT NULL DEFAULT '{}'::jsonb, group_id VARCHAR(100) NOT NULL DEFAULT 'default',
        started_at TIMESTAMPTZ NOT NULL DEFAULT now(), finished_at TIMESTAMPTZ)""",
    """CREATE TABLE soar_run_steps (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        run_id UUID NOT NULL REFERENCES soar_runs(id) ON DELETE CASCADE,
        node_id UUID NOT NULL, action_type VARCHAR(50) NOT NULL, status VARCHAR(20) NOT NULL,
        idempotency_key VARCHAR(255) NOT NULL, input_hash VARCHAR(64) NOT NULL)""",
    "INSERT INTO soar_runs (workflow_id, trigger_type) VALUES (gen_random_uuid(), 'manual')",
]


def _run(coro):
    return _LOOP.run_until_complete(coro)


def test_startup_migration_survives_soar_v2_tables():
    from sqlalchemy import text

    from app.core.database import Base, engine
    import app.models.models  # noqa: F401
    from app.services.soar_schema import migrate_soar

    async def go():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            for stmt in V2_TABLES:
                await conn.execute(text(stmt))
            await conn.run_sync(Base.metadata.create_all)
        await migrate_soar()
        await migrate_soar()  # replicas run it again on every start
        async with engine.connect() as conn:
            cols = lambda t: conn.execute(text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = :t"), {"t": t})
            new_runs = {r[0] for r in await cols("soar_playbook_runs")}
            new_steps = {r[0] for r in await cols("soar_playbook_run_steps")}
            v2_runs = {r[0] for r in await cols("soar_runs")}
            v2_rows = (await conn.execute(text("SELECT count(*) FROM soar_runs"))).scalar()
        await engine.dispose()
        return new_runs, new_steps, v2_runs, v2_rows

    new_runs, new_steps, v2_runs, v2_rows = _run(go())
    assert {"playbook_id", "status", "updated_at", "graph", "context", "waiting_node"} <= new_runs
    assert {"run_id", "node_id", "output_name", "duration_ms"} <= new_steps
    assert "workflow_id" in v2_runs and "updated_at" not in v2_runs   # v2 table untouched
    assert v2_rows == 1                                               # and its data kept
