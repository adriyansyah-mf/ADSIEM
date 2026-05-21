import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import auth, users, agents, ingest, logs, events, alerts, rules, decoders, webhooks, system

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
    decoders.router, webhooks.router, system.router,
]:
    app.include_router(router)
