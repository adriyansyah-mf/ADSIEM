import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base
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
from app.api.routes.correlation import router as correlation_router
from app.api.routes.audit_logs import router as audit_logs_router
from app.api.routes.export import router as export_router
from app.api.routes.suppressions import router as suppressions_router
from app.api.routes.metrics import router as metrics_router
from app.api.routes.handover import router as handover_router
from app.api.routes.hunt_schedules import router as hunt_schedules_router

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
    ("groq_api_key",       "",                          True,  "Groq API key for AI analyst (console.groq.com)"),
    ("groq_model",         "llama-3.3-70b-versatile",   False, "Groq model ID"),
    ("ai_analyst_enabled", "true",                      False, "Enable automatic AI triage on every alert (true/false)"),
    ("searxng_url",        "http://searxng:8080",        False, "Internal URL of SearXNG instance used for threat intel search"),
    ("virustotal_api_key", "",                          True,  "VirusTotal API key — free tier: 500 req/day (virustotal.com)"),
    ("abuseipdb_api_key",  "",                          True,  "AbuseIPDB API key — free tier: 1000 req/day (abuseipdb.com)"),
    ("otx_api_key",        "",                          True,  "AlienVault OTX API key — free (otx.alienvault.com)"),
    ("greynoise_api_key",  "",                          True,  "GreyNoise API key — optional, community endpoint used if empty"),
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
]

async def _seed_settings() -> None:
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.models.models import PlatformSetting
    async with AsyncSessionLocal() as db:
        for key, default, is_secret, description in _DEFAULT_SETTINGS:
            existing = await db.get(PlatformSetting, key)
            if existing is None:
                db.add(PlatformSetting(key=key, value=default, is_secret=is_secret, description=description))
        await db.commit()

async def _seed_correlation_rules() -> None:
    from sqlalchemy import select, func
    from app.core.database import AsyncSessionLocal
    from app.models.models import CorrelationRule
    async with AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(CorrelationRule))).scalar()
        if count == 0:
            db.add(CorrelationRule(
                title="SSH Brute Force Correlation",
                description="Multiple SSH auth failures from same IP",
                match_field="source_ip",
                min_count=10,
                timewindow=300,
                severity_filter=None,
                output_severity="high",
                output_title="[Correlated] {count} alerts from {match_value} in 5 min",
                is_enabled=True,
            ))
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

async def _migrate_alerts_columns() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS duplicate_count INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _seed_settings()
    await _seed_correlation_rules()
    await _migrate_ueba_columns()
    await _migrate_alerts_columns()
    yield

app = FastAPI(title="SIEM Platform API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in [
    auth.router, users.router, agents.router, ingest.router,
    logs.router, events.router, alerts.router, rules.router,
    decoders.router, webhooks.router, system.router, cases_router, settings_router, hygiene_router, ueba_router, fim_router, hunts_router,
    tasks_router, fleet_router, artifacts_router, yara_router,
    enrollment_tokens_router, correlation_router, audit_logs_router,
    export_router, suppressions_router, metrics_router, handover_router,
    hunt_schedules_router,
]:
    app.include_router(router)
