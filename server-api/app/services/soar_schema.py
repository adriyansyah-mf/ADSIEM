# server-api/app/services/soar_schema.py
"""Startup migration for SOAR playbooks and workflow runs (called from app.main).
A module of its own so tests can run it without importing the whole app.

Run history lives in soar_playbook_runs / soar_playbook_run_steps, not
soar_runs / soar_run_steps: databases that once ran feature/soar-engine-core
already hold tables by those names with another schema, which CREATE TABLE IF
NOT EXISTS would silently keep."""
from sqlalchemy import text

from app.core.database import engine


async def migrate_soar() -> None:
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_playbooks (
                id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name               VARCHAR(255) NOT NULL,
                description        TEXT,
                trigger_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                is_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
                group_id           VARCHAR(100) NOT NULL DEFAULT 'default',
                created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_actions (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                playbook_id UUID NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
                action_type VARCHAR(50) NOT NULL,
                order_index INTEGER NOT NULL DEFAULT 0,
                params      JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_actions_playbook_order
            ON soar_actions(playbook_id, order_index)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_playbooks_enabled_group
            ON soar_playbooks(is_enabled, group_id)
        """))
        await conn.execute(text("""
            ALTER TABLE soar_playbooks
            ADD COLUMN IF NOT EXISTS graph JSONB,
            ADD COLUMN IF NOT EXISTS trigger_event VARCHAR(30)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_playbook_runs (
                id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                playbook_id   UUID NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
                group_id      VARCHAR(100) NOT NULL DEFAULT 'default',
                status        VARCHAR(20) NOT NULL DEFAULT 'queued',
                trigger_event VARCHAR(30) NOT NULL,
                alert_id      UUID,
                graph         JSONB NOT NULL,
                context       JSONB NOT NULL DEFAULT '{}'::jsonb,
                waiting_node  VARCHAR(40),
                wait_until    TIMESTAMPTZ,
                error         TEXT,
                created_by    UUID,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                finished_at   TIMESTAMPTZ
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_playbook_run_steps (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id      UUID NOT NULL REFERENCES soar_playbook_runs(id) ON DELETE CASCADE,
                node_id     VARCHAR(40) NOT NULL,
                node_type   VARCHAR(20) NOT NULL,
                status      VARCHAR(20) NOT NULL,
                output_name VARCHAR(20),
                input       JSONB,
                output      JSONB,
                error       TEXT,
                attempts    INTEGER NOT NULL DEFAULT 1,
                started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                duration_ms INTEGER
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_soar_playbook_runs_status ON soar_playbook_runs(status, updated_at)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_soar_playbook_runs_playbook ON soar_playbook_runs(playbook_id, created_at DESC)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_soar_playbook_run_steps_run ON soar_playbook_run_steps(run_id, started_at)"))
