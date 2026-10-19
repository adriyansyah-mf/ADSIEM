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
from app.models.models import (Agent, AgentFirewallRule, AgentLogSource, AgentTask,
                            FimWatchPath)
from app.schemas.schemas import AgentTaskDef, HeartbeatRequest, HeartbeatResponse, LogIngestRequest, LogSourceOut
from app.services.agent_tamper import check_integrity
from app.services.ingest import enqueue_log

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

@router.post("/log", status_code=202)
async def ingest_log(
    body: LogIngestRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    if not agent.approved:
        # accepted, not processed: the agent keeps running quietly until approved
        return {"status": "pending_approval"}
    await enqueue_log(redis, {
        "agent_id": str(agent.id),
        "group_id": agent.group_id,
        "hostname": agent.hostname,
        "log_type": body.log_type,
        "raw_message": body.raw_message,
        "received_at": body.received_at.isoformat(),
        "location": body.location or "",
    })
    return {"status": "queued"}

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    from sqlalchemy import update
    from worker.agent_health import health_event

    def health(event: str, **fields) -> dict:
        return health_event(event, agent_id=agent.id, group_id=agent.group_id, hostname=agent.hostname, **fields)

    now = datetime.now(timezone.utc)
    if body.status == "stopping":
        # Offline now; the worker reports the stop only if the agent stays down
        # (a restart or an upgrade comes back within seconds and clears it).
        await db.execute(update(Agent).where(Agent.id == agent.id).values(
            status="offline", last_seen_at=now, stop_reason=(body.reason or "service_stop")[:30]))
        await db.commit()
        return HeartbeatResponse(config_hash="", log_sources=[])

    integrity_updates, changes = check_integrity(agent, body.version, body.integrity)
    await db.execute(
        update(Agent).where(Agent.id == agent.id)
        .values(status="online", last_seen_at=now, version=body.version, stop_reason=None, **integrity_updates)
    )
    await db.commit()
    if agent.approved:
        for change in changes:
            await enqueue_log(redis, health("agent_integrity_changed", **change))

    result = await db.execute(
        select(AgentLogSource).where(AgentLogSource.agent_id == agent.id)
    )
    sources = result.scalars().all()

    fim_result = await db.execute(
        select(FimWatchPath).where(FimWatchPath.is_enabled == True).order_by(FimWatchPath.path)
    )
    fim_paths = [p.path for p in fim_result.scalars().all()]

    # fetch pending tasks for this agent and mark them dispatched (none before approval)
    pending_tasks = []
    if agent.approved:
        task_result = await db.execute(
            select(AgentTask).where(AgentTask.agent_id == agent.id, AgentTask.status == "pending")
        )
        pending_tasks = task_result.scalars().all()
    task_ids = [t.id for t in pending_tasks]
    if task_ids:
        from sqlalchemy import update as _update
        await db.execute(
            _update(AgentTask).where(AgentTask.id.in_(task_ids)).values(status="dispatched")
        )
        await db.commit()

    sources_data = [{"path": s.path, "log_type": s.log_type, "is_enabled": s.is_enabled} for s in sources]

    fw_result = await db.execute(
        select(AgentFirewallRule)
        .where(AgentFirewallRule.agent_id == agent.id, AgentFirewallRule.is_enabled == True)
        .order_by(AgentFirewallRule.created_at)
    )
    fw_rules = fw_result.scalars().all()
    firewall_data = [
        {
            "id": str(r.id),
            "action": r.action,
            "cidr": r.cidr,
            "proto": r.proto,
            "port": r.port,
            "direction": r.direction,
            "ttl_seconds": r.ttl_seconds,
            "reason": r.reason,
        }
        for r in fw_rules
    ]

    config_hash = hashlib.sha256(
        json.dumps(
            {"sources": sources_data, "fim_paths": fim_paths, "firewall": firewall_data},
            sort_keys=True,
        ).encode()
    ).hexdigest()

    return HeartbeatResponse(
        config_hash=config_hash,
        log_sources=[LogSourceOut.model_validate(s) for s in sources],
        fim_paths=fim_paths,
        tasks=[AgentTaskDef(id=t.id, task_type=t.task_type, params=t.params or {}) for t in pending_tasks],
        firewall=firewall_data,
    )
