import json
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter
from app.core.database import engine, Base
from app.core.es_client import ensure_index as ensure_es_index
import app.models.models  # noqa: F401 — ensure all models are registered before create_all
from app.api.routes import auth, users, agents, ingest, logs, events, alerts, rules, decoders, webhooks, system
from app.api.routes.cases import router as cases_router
from app.api.routes.settings import router as settings_router
from app.api.routes.hygiene import router as hygiene_router
from app.api.routes.ueba import router as ueba_router
from app.api.routes.fim import router as fim_router
from app.api.routes.hunts import router as hunts_router
from app.api.routes.tasks import router as tasks_router, fleet_router
from app.api.routes.artifacts import router as artifacts_router
from app.api.routes.yara_rules import router as yara_router
from app.api.routes.enrollment_tokens import router as enrollment_tokens_router
from app.api.routes.api_keys import router as api_keys_router
from app.api.routes.queues import router as queues_router
from app.api.routes.sla_policies import router as sla_policies_router
from app.api.routes.iocs import router as iocs_router
from app.api.routes.entities import router as entities_router
from app.api.routes.investigation import router as investigation_router
from app.api.routes.exports import router as exports_router
from app.api.routes.retention_policies import router as retention_policies_router
from app.api.routes.audit_logs import router as audit_logs_router
from app.api.routes.export import router as export_router
from app.api.routes.suppressions import router as suppressions_router
from app.api.routes.metrics import router as metrics_router
from app.api.routes.handover import router as handover_router
from app.api.routes.hunt_schedules import router as hunt_schedules_router
from app.api.routes.sop import router as sop_router
from app.api.routes.soar import router as soar_router
from app.api.routes.search import router as search_router
from app.api.routes.reports import router as reports_router
from app.api.routes.assistant import router as assistant_router
from app.api.routes.mitre import router as mitre_router
from app.api.routes.command_center import router as command_center_router
from app.api.routes.ws import router as ws_router, manager as ws_manager

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        __import__("logging").getLevelName(settings.LOG_LEVEL.upper())
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)

_DEFAULT_SETTINGS = [
    ("org_name",           "",                          False, "Organization name shown on generated PDF reports"),
    ("ninerouter_api_key", "",                          True,  "9router API key for AI analyst — generate via POST /api/keys against the 9router dashboard API (see docs/PROJECT_OVERVIEW.md)"),
    ("ninerouter_model",   "combo",                      False, "9router combo name to route AI analyst requests through"),
    ("ninerouter_search_provider", "searxng",            False, "9router /v1/search provider/combo for AI research queries (searxng, tavily, or a dashboard search-combo for multi-provider auto-fallback)"),
    ("ai_analyst_enabled", "true",                      False, "Enable automatic AI triage on every alert (true/false)"),
    ("ai_confidence_threshold","0.0",                    False, "Minimum AI confidence (0.0-1.0) to create/escalate a case — notes always written regardless"),
    ("ai_min_severity",    "high",                      False, "Minimum alert severity investigated by the AI analyst (info/low/medium/high/critical)"),
    ("searxng_url",        "http://searxng:8080",        False, "Internal URL of SearXNG instance used for threat intel search"),
    ("virustotal_api_key", "",                          True,  "VirusTotal API key — free tier: 500 req/day (virustotal.com)"),
    ("abuseipdb_api_key",  "",                          True,  "AbuseIPDB API key — free tier: 1000 req/day (abuseipdb.com)"),
    ("otx_api_key",        "",                          True,  "AlienVault OTX API key — free (otx.alienvault.com)"),
    ("greynoise_api_key",  "",                          True,  "GreyNoise API key — optional, community endpoint used if empty"),
    ("shodan_api_key",     "",                          True,  "Shodan API key — enables exposed-port/CVE lookup for IPs seen in alerts (shodan.io/product/api)"),
    ("smtp_enabled",      "false",     False, "Enable email alert notifications (true/false)"),
    ("smtp_host",         "",          False, "SMTP server hostname (e.g. smtp.gmail.com)"),
    ("smtp_port",         "587",       False, "SMTP port (587=STARTTLS, 465=SSL, 25=plain)"),
    ("smtp_user",         "",          False, "SMTP username / login email"),
    ("smtp_password",     "",          True,  "SMTP password or app password"),
    ("smtp_from",         "",          False, "From address (defaults to smtp_user if empty)"),
    ("smtp_to",           "",          False, "Comma-separated recipient email addresses"),
    ("smtp_min_severity", "high",      False, "Minimum severity to email (info/low/medium/high/critical)"),
    ("retention_raw_logs_days",  "30",  False, "Delete raw_logs older than N days (0=disabled)"),
    ("retention_events_days",    "90",  False, "Delete events older than N days (0=disabled)"),
    ("retention_alerts_days",   "180",  False, "Delete closed alerts older than N days (0=disabled)"),
    ("auto_assign_alerts",       "false", False, "Assign new alerts to the least-loaded active analyst"),
    ("correlation_definitions",  "[]",    False, "JSON array of grouped sequence/threshold correlation definitions"),
    ("soar_destructive_approval_required", "true", False, "Require approval before isolate-agent or block-IP SOAR actions"),
]

async def _seed_settings() -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.models import PlatformSetting
    async with AsyncSessionLocal() as db:
        for key, default, is_secret, description in _DEFAULT_SETTINGS:
            existing = await db.get(PlatformSetting, key)
            if existing is None:
                db.add(PlatformSetting(key=key, value=default, is_secret=is_secret, description=description))
        await db.commit()

async def _migrate_ueba_columns() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE ueba_anomalies
            ADD COLUMN IF NOT EXISTS mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS ai_narrative TEXT,
            ADD COLUMN IF NOT EXISTS ai_action VARCHAR(20),
            ADD COLUMN IF NOT EXISTS case_id UUID REFERENCES cases(id) ON DELETE SET NULL
        """))
        await conn.execute(text("""
            ALTER TABLE ueba_entity_scores
            ADD COLUMN IF NOT EXISTS feature_profile JSONB NOT NULL DEFAULT '{}'::jsonb
        """))
        await conn.execute(text("""
            ALTER TABLE ueba_feature_snapshots
            ADD COLUMN IF NOT EXISTS risk_score FLOAT NOT NULL DEFAULT 0.0
        """))
        await conn.execute(text("""
            ALTER TABLE ueba_anomalies
            ADD COLUMN IF NOT EXISTS hash_ti_hits JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS domain_ti_hits JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS url_ti_hits JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS ip_ti_hits JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS powershell_hits JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS command_hits JSONB NOT NULL DEFAULT '[]'::jsonb
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ueba_anomalies_case_id
            ON ueba_anomalies(case_id)
            WHERE case_id IS NOT NULL
        """))
        # Performance indexes for multi-tenant queries and sorted lists
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ueba_entity_scores_group_risk
            ON ueba_entity_scores(group_id, risk_score DESC)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ueba_anomalies_group_detected
            ON ueba_anomalies(group_id, detected_at DESC)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ueba_anomalies_entity_detected
            ON ueba_anomalies(entity_type, entity_value, detected_at DESC)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ueba_snapshots_group_type_hour
            ON ueba_feature_snapshots(group_id, entity_type, snapshot_hour DESC)
        """))

async def _migrate_agent_telemetry_columns() -> None:
    """Fleet-health telemetry (AGENT_PRODUCTION_IMPROVEMENT_ROADMAP.md P0-B) —
    real signals from the agent's existing in-memory buffer, sent with every
    heartbeat: current queue depth, cumulative drops, oldest-queued-item age,
    and process uptime. Not the full durable-spool rewrite (P0-A)."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE agents
            ADD COLUMN IF NOT EXISTS buffer_depth INTEGER,
            ADD COLUMN IF NOT EXISTS buffer_dropped_total BIGINT NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS oldest_buffered_event_age_seconds INTEGER,
            ADD COLUMN IF NOT EXISTS uptime_seconds INTEGER
        """))


async def _migrate_alerts_columns() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS duplicate_count INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS ai_verdict VARCHAR(50)
            ,ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(255)
            ,ADD COLUMN IF NOT EXISTS correlation_key VARCHAR(512)
            ,ADD COLUMN IF NOT EXISTS source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        """))
        await conn.execute(text("""
            ALTER TABLE cases
            ADD COLUMN IF NOT EXISTS ai_confidence FLOAT
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS alert_suppressions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                entity_type VARCHAR(50) NOT NULL,
                entity_value VARCHAR(500) NOT NULL,
                reason TEXT,
                group_id VARCHAR(100) NOT NULL DEFAULT 'default',
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_by UUID REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shift_handovers (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                group_id VARCHAR(100) NOT NULL DEFAULT 'default',
                shift_label VARCHAR(50) NOT NULL DEFAULT 'day',
                summary TEXT NOT NULL DEFAULT '',
                open_alerts INTEGER NOT NULL DEFAULT 0,
                open_cases INTEGER NOT NULL DEFAULT 0,
                escalations INTEGER NOT NULL DEFAULT 0,
                created_by UUID REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS alert_notes (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                author_id UUID REFERENCES users(id) ON DELETE SET NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_alert_notes_alert_id ON alert_notes(alert_id)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS hunt_schedules (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(200) NOT NULL,
                ioc_type VARCHAR(50) NOT NULL,
                ioc_value VARCHAR(500) NOT NULL,
                interval_hours INTEGER NOT NULL DEFAULT 24,
                group_id VARCHAR(100) NOT NULL DEFAULT 'default',
                is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                last_run_at TIMESTAMPTZ,
                created_by UUID REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS case_embeddings (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                embedding    vector(384) NOT NULL,
                summary_text TEXT NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT uq_case_embeddings_case_id UNIQUE (case_id)
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_case_embeddings_group
            ON case_embeddings(group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_case_embeddings_ivfflat
            ON case_embeddings
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 10)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sop_documents (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                filename     VARCHAR(500) NOT NULL,
                content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
                raw_text     TEXT NOT NULL,
                status       VARCHAR(20) NOT NULL DEFAULT 'pending',
                uploaded_by  UUID REFERENCES users(id) ON DELETE SET NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_documents_group
            ON sop_documents(group_id)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sop_chunks (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                document_id  UUID NOT NULL REFERENCES sop_documents(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                chunk_index  INTEGER NOT NULL,
                chunk_text   TEXT NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            ALTER TABLE sop_chunks
            ADD COLUMN IF NOT EXISTS embedding vector(384)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_chunks_group
            ON sop_chunks(group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_chunks_ivfflat
            ON sop_chunks
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 10)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS feedback_embeddings (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                feedback_id  UUID NOT NULL REFERENCES ai_feedback(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                embedding    vector(384) NOT NULL,
                rating       VARCHAR(20) NOT NULL,
                summary_text TEXT NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT uq_feedback_embeddings_feedback_id UNIQUE (feedback_id)
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_feedback_embeddings_group
            ON feedback_embeddings(group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_feedback_embeddings_ivfflat
            ON feedback_embeddings
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 10)
        """))

async def _migrate_soar_tables() -> None:
    from sqlalchemy import text
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

async def _migrate_soar_v2_tables() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_workflows (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name            VARCHAR(255) NOT NULL,
                description     TEXT,
                is_enabled      BOOLEAN NOT NULL DEFAULT true,
                group_id        VARCHAR(100) NOT NULL DEFAULT 'default',
                created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_nodes (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workflow_id  UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
                node_type    VARCHAR(50) NOT NULL,
                name         VARCHAR(255) NOT NULL,
                config       JSONB NOT NULL DEFAULT '{}'::jsonb,
                pos_x        DOUBLE PRECISION NOT NULL DEFAULT 0,
                pos_y        DOUBLE PRECISION NOT NULL DEFAULT 0
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_edges (
                id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workflow_id    UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
                source_node_id UUID NOT NULL REFERENCES soar_nodes(id) ON DELETE CASCADE,
                source_handle  VARCHAR(50) NOT NULL DEFAULT 'out',
                target_node_id UUID NOT NULL REFERENCES soar_nodes(id) ON DELETE CASCADE
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_runs (
                id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workflow_id    UUID NOT NULL REFERENCES soar_workflows(id) ON DELETE CASCADE,
                status         VARCHAR(20) NOT NULL DEFAULT 'pending',
                trigger_type   VARCHAR(30) NOT NULL,
                trigger_ref    JSONB NOT NULL DEFAULT '{}'::jsonb,
                current_node_id UUID REFERENCES soar_nodes(id),
                variables      JSONB NOT NULL DEFAULT '{}'::jsonb,
                resume_at      TIMESTAMPTZ,
                group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
                started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
                finished_at    TIMESTAMPTZ
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_run_steps (
                id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                run_id              UUID NOT NULL REFERENCES soar_runs(id) ON DELETE CASCADE,
                node_id             UUID NOT NULL REFERENCES soar_nodes(id),
                action_type         VARCHAR(50) NOT NULL,
                status              VARCHAR(20) NOT NULL,
                is_destructive      BOOLEAN NOT NULL DEFAULT false,
                is_reversible       BOOLEAN NOT NULL DEFAULT false,
                actor_id            UUID REFERENCES users(id) ON DELETE SET NULL,
                acted_at            TIMESTAMPTZ,
                idempotency_key     VARCHAR(255) NOT NULL,
                input_hash          VARCHAR(64) NOT NULL,
                rollback_of_step_id UUID REFERENCES soar_run_steps(id) ON DELETE RESTRICT,
                input               JSONB,
                output              JSONB,
                error               TEXT,
                started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
                finished_at         TIMESTAMPTZ
            )
        """))
        await conn.execute(text("""
            ALTER TABLE soar_run_steps
            ADD COLUMN IF NOT EXISTS action_type VARCHAR(50) NOT NULL DEFAULT 'unknown',
            ADD COLUMN IF NOT EXISTS is_destructive BOOLEAN NOT NULL DEFAULT false,
            ADD COLUMN IF NOT EXISTS is_reversible BOOLEAN NOT NULL DEFAULT false,
            ADD COLUMN IF NOT EXISTS actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
            ADD COLUMN IF NOT EXISTS acted_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(255),
            ADD COLUMN IF NOT EXISTS input_hash VARCHAR(64),
            ADD COLUMN IF NOT EXISTS rollback_of_step_id UUID REFERENCES soar_run_steps(id) ON DELETE RESTRICT
        """))
        await conn.execute(text("""
            UPDATE soar_run_steps
            SET idempotency_key = 'legacy-' || id::text
            WHERE idempotency_key IS NULL
        """))
        await conn.execute(text("""
            UPDATE soar_run_steps
            SET input_hash = repeat('0', 64)
            WHERE input_hash IS NULL
        """))
        await conn.execute(text("""
            ALTER TABLE soar_run_steps
            ALTER COLUMN idempotency_key SET NOT NULL,
            ALTER COLUMN input_hash SET NOT NULL
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_workflows_enabled_group
            ON soar_workflows(is_enabled, group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_nodes_workflow_id
            ON soar_nodes(workflow_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_edges_workflow_id
            ON soar_edges(workflow_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_edges_source_node_id
            ON soar_edges(source_node_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_runs_workflow_status
            ON soar_runs(workflow_id, status)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_runs_status_resume
            ON soar_runs(status, resume_at)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_soar_run_steps_run_id
            ON soar_run_steps(run_id)
        """))
        await conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_soar_run_steps_idempotency
            ON soar_run_steps(run_id, idempotency_key)
        """))

async def _migrate_webhook_payload_format() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS payload_format VARCHAR(50) NOT NULL DEFAULT 'default'"))

async def _migrate_mfa_columns() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE"))

async def _migrate_audit_chain() -> None:
    """Add tamper-evident audit-chain columns/tables, seed audit:verify, and
    backfill pre-existing audit_logs rows into a verifiable genesis segment.

    The backfill is idempotent: it only processes rows where chain_hash IS
    NULL, so a restart after the first successful run does no work. Rows are
    grouped per tenant via a best-effort actor_id -> users.group_id lookup
    (actor_id IS NULL, e.g. a failed login, falls back to the unscoped
    "__unscoped__" chain) and hashed in chronological order using the exact
    same canonical payload/hash functions the live append path uses, so
    verification treats historical and newly-appended rows identically.
    """
    from sqlalchemy import text
    from app.services.audit import GENESIS_HASH, UNSCOPED_GROUP, _canonical_json, _canonical_payload, _sha256_hex

    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_type VARCHAR(20) NOT NULL DEFAULT 'user'"))
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS group_id VARCHAR(100)"))
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS payload_hash VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS chain_hash VARCHAR(64)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_logs_group_id ON audit_logs(group_id)"))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_chain_heads (
                group_id   VARCHAR(100) PRIMARY KEY,
                chain_hash VARCHAR(64) NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        await conn.execute(text(
            "INSERT INTO permissions (name) VALUES ('audit:verify') ON CONFLICT (name) DO NOTHING"
        ))
        await conn.execute(text("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id FROM roles r, permissions p
            WHERE r.name IN ('superadmin', 'admin') AND p.name = 'audit:verify'
            ON CONFLICT DO NOTHING
        """))

        pending = (await conn.execute(text("""
            SELECT al.id, al.actor_id, al.action, al.resource_type, al.resource_id,
                   al.detail, al.created_at, u.group_id AS user_group_id
            FROM audit_logs al
            LEFT JOIN users u ON u.id = al.actor_id
            WHERE al.chain_hash IS NULL
            ORDER BY al.created_at ASC, al.id ASC
        """))).mappings().all()

        by_group: dict[str, list] = {}
        for row in pending:
            group = row["user_group_id"] or UNSCOPED_GROUP
            by_group.setdefault(group, []).append(row)

        for group_id, rows in by_group.items():
            head = (await conn.execute(
                text("SELECT chain_hash FROM audit_chain_heads WHERE group_id = :group_id FOR UPDATE"),
                {"group_id": group_id},
            )).scalar_one_or_none()
            if head is None:
                await conn.execute(
                    text("INSERT INTO audit_chain_heads (group_id, chain_hash) VALUES (:group_id, :hash)"),
                    {"group_id": group_id, "hash": GENESIS_HASH},
                )
                previous_hash = GENESIS_HASH
            else:
                previous_hash = head

            for row in rows:
                actor_type = "system" if row["actor_id"] is None else "user"
                payload = _canonical_payload(
                    actor_type=actor_type,
                    actor_id=row["actor_id"],
                    group_id=group_id,
                    action=row["action"],
                    resource_type=row["resource_type"],
                    resource_id=row["resource_id"],
                    detail=row["detail"] or {},
                    request_id=None,
                    created_at=row["created_at"],
                )
                payload_hash = _sha256_hex(_canonical_json(payload))
                chain_hash = _sha256_hex(previous_hash + payload_hash)
                await conn.execute(text("""
                    UPDATE audit_logs
                    SET actor_type = :actor_type, group_id = :group_id, request_id = NULL,
                        payload_hash = :payload_hash, previous_hash = :previous_hash, chain_hash = :chain_hash
                    WHERE id = :id
                """), {
                    "actor_type": actor_type, "group_id": group_id, "payload_hash": payload_hash,
                    "previous_hash": previous_hash, "chain_hash": chain_hash, "id": row["id"],
                })
                previous_hash = chain_hash

            await conn.execute(
                text("UPDATE audit_chain_heads SET chain_hash = :hash, updated_at = NOW() WHERE group_id = :group_id"),
                {"hash": previous_hash, "group_id": group_id},
            )

async def _migrate_webhook_dlq_columns() -> None:
    """Add the typed dead-letter fields to webhook_deliveries and seed
    queues:manage for existing databases (mirrors the api_keys/audit_verify
    pattern — db/init.sql's seed block only runs once against a fresh volume)."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS group_id VARCHAR(100)"))
        await conn.execute(text("ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS last_error TEXT"))
        await conn.execute(text("ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS error_class VARCHAR(100)"))
        await conn.execute(text("ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS first_failed_at TIMESTAMPTZ"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_group_id ON webhook_deliveries(group_id)"))
        await conn.execute(text(
            "INSERT INTO permissions (name) VALUES ('queues:manage') ON CONFLICT (name) DO NOTHING"
        ))
        await conn.execute(text("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id FROM roles r, permissions p
            WHERE r.name IN ('superadmin', 'admin') AND p.name = 'queues:manage'
            ON CONFLICT DO NOTHING
        """))
        # Best-effort backfill: existing rows created before group_id existed
        # get it from their alert's group_id where resolvable.
        await conn.execute(text("""
            UPDATE webhook_deliveries wd
            SET group_id = a.group_id
            FROM alerts a
            WHERE wd.alert_id = a.id AND wd.group_id IS NULL
        """))

async def _migrate_api_keys_permission() -> None:
    """The `api_keys` table itself is created by Base.metadata.create_all; this only
    seeds the api_keys:manage permission for existing databases, since db/init.sql's
    seed block only runs once against a fresh Postgres volume."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO permissions (name) VALUES ('api_keys:manage') ON CONFLICT (name) DO NOTHING"
        ))
        await conn.execute(text("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id FROM roles r, permissions p
            WHERE r.name IN ('superadmin', 'admin') AND p.name = 'api_keys:manage'
            ON CONFLICT DO NOTHING
        """))

async def _migrate_ioc_tables_permission() -> None:
    """The ioc_observations/ioc_links tables themselves are created by
    Base.metadata.create_all; this only seeds the iocs:read permission for
    existing databases, since db/init.sql's seed block only runs once
    against a fresh Postgres volume."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO permissions (name) VALUES ('iocs:read') ON CONFLICT (name) DO NOTHING"
        ))
        await conn.execute(text("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id FROM roles r, permissions p
            WHERE r.name IN ('superadmin', 'admin', 'analyst') AND p.name = 'iocs:read'
            ON CONFLICT DO NOTHING
        """))

async def _ws_redis_listener():
    """Subscribe to Redis ws:alerts channel and broadcast to WebSocket clients."""
    import asyncio
    import redis.asyncio as aioredis
    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe("ws:alerts")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await ws_manager.broadcast(data)
                except Exception:
                    pass
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe("ws:alerts")
        await redis.aclose()


_STARTUP_LOCK_KEY = 727501001  # arbitrary fixed key for the session-level advisory lock below


async def _migrate_rule_revisions() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO rule_revisions (id, rule_id, version, content, created_at) "
            "SELECT gen_random_uuid(), id, version, content, NOW() FROM rules r "
            "WHERE NOT EXISTS (SELECT 1 FROM rule_revisions rr WHERE rr.rule_id = r.id)"
        ))

async def lifespan(app: FastAPI):
    from sqlalchemy import text
    # Multiple server-api replicas start concurrently (docker compose recreates
    # both at once). Without this lock they'd all run create_all + the
    # _migrate_* ALTER TABLE statements at the same time, and Postgres
    # serializes concurrent ALTER TABLE on the same relation — with enough
    # migration functions this chain of AccessExclusiveLock waits can stall
    # for a very long time (observed: 70s+, health check timing out and the
    # container never becoming ready). A session-level advisory lock makes
    # only one replica run migrations at a time; the rest wait briefly, then
    # find everything already exists via IF NOT EXISTS and proceed instantly.
    lock_conn = await engine.connect()
    await lock_conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _STARTUP_LOCK_KEY})
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _migrate_rule_revisions()
        await _seed_settings()
        await _migrate_ueba_columns()
        await _migrate_alerts_columns()
        await _migrate_soar_tables()
        await _migrate_soar_v2_tables()
        await _migrate_webhook_payload_format()
        await _migrate_mfa_columns()
        await _migrate_api_keys_permission()
        await _migrate_audit_chain()
        await _migrate_webhook_dlq_columns()
        await _migrate_ioc_tables_permission()
        await _migrate_agent_telemetry_columns()
    finally:
        await lock_conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _STARTUP_LOCK_KEY})
        await lock_conn.close()
    await ensure_es_index()
    import asyncio
    _listener_task = asyncio.create_task(_ws_redis_listener())
    yield
    _listener_task.cancel()

app = FastAPI(title="SIEM Platform API", version="1.0.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _security_headers(request, call_next):
    """Defense-in-depth security headers set at the API layer directly, for
    any deployment or test path that talks to this app without nginx in
    front (e.g. the dev container's exposed port, or a bare TestClient).
    When nginx IS in front (both nginx.conf and nginx.prod.conf), it hides
    these same headers via proxy_hide_header before adding its own —
    nginx is the single authoritative source for the header a client
    actually receives in every deployed configuration; this middleware never
    competes with it.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com"
    )
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

for router in [
    auth.router, users.router, agents.router, ingest.router,
    logs.router, events.router, alerts.router, rules.router,
    decoders.router, webhooks.router, system.router, cases_router, settings_router, hygiene_router, ueba_router, fim_router, hunts_router,
    tasks_router, fleet_router, artifacts_router, yara_router,
    enrollment_tokens_router, audit_logs_router,
    export_router, suppressions_router, metrics_router, handover_router,
    hunt_schedules_router, sop_router, soar_router, search_router,
    reports_router, assistant_router, mitre_router, ws_router,
    api_keys_router,
    queues_router,
    sla_policies_router,
    iocs_router,
    entities_router,
    investigation_router,
    exports_router,
    retention_policies_router,
    command_center_router,
]:
    app.include_router(router)
