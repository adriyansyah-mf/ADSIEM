# server-api/app/api/routes/ingest.py
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_agent
from app.core.redis_client import get_redis
from app.core.security import hash_token
from app.models.models import (Agent, AgentFirewallRule, AgentLogSource, AgentTask,
                            FimWatchPath)
from app.schemas.schemas import EvidenceEnvelope, EvidenceReceipt, AgentTaskDef, HeartbeatRequest, HeartbeatResponse, LogIngestRequest, LogSourceOut
from app.services.agent_tamper import check_integrity, heartbeat_anomaly, uninstall_token_sha256
from app.services import yara_ruleset
from app.services.ingest import enqueue_log
from app.services.evidence_inbox import (MAX_BATCH_EVENTS, MAX_BATCH_REQUEST_BYTES, MAX_REQUEST_BYTES,
                                        accept_evidence, accept_evidence_batch, check_evidence_durability)

router = APIRouter(prefix="/api/ingest", tags=["ingest"])
log = structlog.get_logger()

# Shared with worker/worker/agent_monitor.py (it reads LAST_LOG_KEY).
LAST_LOG_KEY = "siem:agent:lastlog:{}"
HB_STATE_KEY = "siem:agent:hb:{}"
HB_ANOMALY_KEY = "siem:agent:hb_anomaly:{}:{}"  # one event per agent and kind per 10 min


async def _session_anomaly(redis: aioredis.Redis, agent_id, body: HeartbeatRequest) -> str | None:
    """Heartbeat continuity (agent_tamper.heartbeat_anomaly), state kept in Redis.
    Best-effort: Redis trouble must never fail a heartbeat."""
    if not body.session:
        return None
    try:
        key = HB_STATE_KEY.format(agent_id)
        state, anomaly = heartbeat_anomaly(await redis.hgetall(key) or {}, body.session, body.seq, time.time())
        await redis.hset(key, mapping={k: str(v) for k, v in state.items()})
        await redis.expire(key, 86400)
        if anomaly and await redis.set(HB_ANOMALY_KEY.format(agent_id, anomaly), "1", ex=600, nx=True):
            return anomaly
    except Exception as exc:  # noqa: BLE001
        log.warning("heartbeat_session_check_failed", agent_id=str(agent_id), error=str(exc))
    return None

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
    try:  # for "heartbeat alive, logs stopped" (worker agent_monitor)
        await redis.set(LAST_LOG_KEY.format(agent.id), int(time.time()), ex=30 * 86400)
    except Exception as exc:  # noqa: BLE001
        log.warning("last_log_mark_failed", agent_id=str(agent.id), error=str(exc))
    return {"status": "queued"}

@router.post("/v2/log", status_code=202, response_model=EvidenceReceipt)
async def ingest_evidence(
    request: Request,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EvidenceReceipt:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid_content_length") from exc
        if length < 0:
            raise HTTPException(status_code=400, detail="invalid_content_length")
        if length > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="evidence_request_too_large")
    encoded = bytearray()
    async for chunk in request.stream():
        if len(encoded) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="evidence_request_too_large")
        encoded.extend(chunk)
    try:
        body = EvidenceEnvelope.model_validate_json(encoded)
    except ValidationError as exc:
        # Do not echo rejected evidence (or invalid Unicode) in response/logs.
        raise HTTPException(status_code=422, detail="invalid_evidence_envelope") from exc
    return await accept_evidence(db, agent, body)


@router.post("/v2/logs", status_code=200)
async def ingest_evidence_batch(
    request: Request,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Durable evidence in batches: {"protocol_version": 2, "events": [...]},
    one result per event (see accept_evidence_batch)."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BATCH_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="evidence_request_too_large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid_content_length") from exc
    encoded = bytearray()
    async for chunk in request.stream():
        if len(encoded) + len(chunk) > MAX_BATCH_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="evidence_request_too_large")
        encoded.extend(chunk)
    try:
        body = json.loads(encoded)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid_evidence_batch") from exc
    events = body.get("events") if isinstance(body, dict) else None
    if (not isinstance(body, dict) or type(body.get("protocol_version")) is not int or body["protocol_version"] != 2
            or not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH_EVENTS):
        raise HTTPException(status_code=422, detail="invalid_evidence_batch")
    return {"protocol_version": 2, "results": await accept_evidence_batch(db, agent, events)}


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
    # Durable agents report evidence health; stamp it with our receipt time.
    # Heartbeats without it (legacy agents) keep the last known snapshot.
    evidence = ({"evidence_health": body.evidence_health.model_dump(mode="json"), "evidence_health_at": now}
                if body.evidence_health is not None else {})
    anomaly = await _session_anomaly(redis, agent.id, body)
    if anomaly and agent.approved:
        await enqueue_log(redis, health("agent_heartbeat_anomaly", kind=anomaly, session=body.session,
                                        seq=body.seq, version=body.version))
    if body.status == "stopping":
        # Offline now; the worker reports the stop only if the agent stays down
        # (a restart or an upgrade comes back within seconds and clears it).
        await db.execute(update(Agent).where(Agent.id == agent.id).values(
            status="offline", last_seen_at=now, stop_reason=(body.reason or "service_stop")[:30], **evidence))
        await db.commit()
        protocols = [2] if settings.EVIDENCE_INGEST_ENABLED and await check_evidence_durability(db) else []
        return HeartbeatResponse(config_hash="", log_sources=[], evidence_protocols=protocols,
                                 evidence_batch_max=MAX_BATCH_EVENTS if protocols else 0)

    integrity_updates, changes = check_integrity(agent, body.version, body.integrity)
    await db.execute(
        update(Agent).where(Agent.id == agent.id)
        .values(status="online", last_seen_at=now, version=body.version, stop_reason=None,
                **integrity_updates, **evidence)
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

    yara_hash, _ = await yara_ruleset.enabled_ruleset(db)
    config_hash = hashlib.sha256(
        json.dumps(
            {"sources": sources_data, "fim_paths": fim_paths, "firewall": firewall_data, "yara": yara_hash},
            sort_keys=True,
        ).encode()
    ).hexdigest()

    protocols = [2] if settings.EVIDENCE_INGEST_ENABLED and await check_evidence_durability(db) else []
    return HeartbeatResponse(
        evidence_protocols=protocols,
        evidence_batch_max=MAX_BATCH_EVENTS if protocols else 0,
        config_hash=config_hash,
        log_sources=[LogSourceOut.model_validate(s) for s in sources],
        fim_paths=fim_paths,
        tasks=[AgentTaskDef(id=t.id, task_type=t.task_type, params=t.params or {}) for t in pending_tasks],
        firewall=firewall_data,
        uninstall_token_sha256=uninstall_token_sha256(agent.id),
        yara_rules_hash=yara_hash,
    )


@router.post("/yara-rules")
async def agent_yara_rules(
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """The enabled YARA rules for on-access scanning (heartbeats carry
    only their hash)."""
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    digest, rules = await yara_ruleset.enabled_ruleset(db)
    return {"hash": digest, "rules": rules}
