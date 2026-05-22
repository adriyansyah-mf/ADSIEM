import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
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

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        __import__("logging").getLevelName(settings.LOG_LEVEL.upper())
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)

@asynccontextmanager
async def lifespan(app: FastAPI):
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
]:
    app.include_router(router)
