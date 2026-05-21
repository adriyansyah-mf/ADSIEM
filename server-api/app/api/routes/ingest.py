# server-api/app/api/routes/ingest.py
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.database import get_db
from app.core.deps import get_agent
from app.core.redis_client import get_redis
from app.core.security import hash_token
from app.models.models import Agent, AgentLogSource
from app.schemas.schemas import HeartbeatRequest, HeartbeatResponse, LogIngestRequest, LogSourceOut
from app.services.ingest import enqueue_log

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

@router.post("/log", status_code=202)
async def ingest_log(
    body: LogIngestRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    await enqueue_log(redis, {
        "agent_id": str(agent.id),
        "group_id": agent.group_id,
        "hostname": agent.hostname,
        "log_type": body.log_type,
        "raw_message": body.raw_message,
        "received_at": body.received_at.isoformat(),
    })
    return {"status": "queued"}

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    from sqlalchemy import update
    await db.execute(
        update(Agent).where(Agent.id == agent.id)
        .values(status="online", last_seen_at=datetime.now(timezone.utc), version=body.version)
    )
    await db.commit()

    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.agent_id == agent.id)
    )
    sources = result.scalars().all()
    sources_data = [{"path": s.path, "log_type": s.log_type, "is_enabled": s.is_enabled} for s in sources]
    config_hash = hashlib.sha256(json.dumps(sources_data, sort_keys=True).encode()).hexdigest()

    return HeartbeatResponse(
        config_hash=config_hash,
        log_sources=[LogSourceOut.model_validate(s) for s in sources],
    )
