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

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _seed_settings()
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
    enrollment_tokens_router,
]:
    app.include_router(router)
