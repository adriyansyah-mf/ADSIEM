# server-api/app/api/routes/evidence.py
"""Durable evidence delivery per agent: the last health snapshot the agent
reported, the server inbox for it, and operator retry of dead letters."""
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, EvidenceInbox, User
from app.services.audit import audit_log

router = APIRouter(tags=["evidence"])

# A queue older than this, or one the sender is retrying, is a backlog.
BACKLOG_AGE = timedelta(minutes=5)
DEAD_LETTER_LIMIT = 50


def evidence_status(health: dict | None, reported_at: datetime | None, now: datetime) -> dict:
    """healthy / backlogged / blocked / degraded / not_reported, plus staleness.

    An online heartbeat alone never means evidence delivery is healthy: agents
    that do not report (legacy mode) are not_reported. A stale report keeps its
    last known status and says it is stale."""
    if not health or reported_at is None:
        return {"status": "not_reported", "reason": None, "reported_at": None, "stale": False}
    stale = now - reported_at > timedelta(seconds=2 * settings.AGENT_HEARTBEAT_INTERVAL_SECONDS)
    sender = health.get("sender") or {}
    oldest = health.get("oldest_queued_at")
    old_queue = False
    if oldest:
        try:
            old_queue = now - datetime.fromisoformat(oldest.replace("Z", "+00:00")) > BACKLOG_AGE
        except ValueError:
            old_queue = False
    if health.get("state") == "degraded":
        status, reason = "degraded", health.get("reason") or None
    elif sender.get("state") == "blocked":
        status, reason = "blocked", sender.get("reason") or None
    elif health.get("queued_events", 0) > 0 and (old_queue or sender.get("state") == "retrying"):
        status, reason = "backlogged", sender.get("reason") or "backlog"
    else:
        status, reason = "healthy", None
    return {"status": status, "reason": reason, "reported_at": reported_at.isoformat(), "stale": stale}


def _in_scope(group_filter: str | None):
    # receipts keep the group they were accepted under; scope by that, not the agent's current group
    return true() if group_filter is None else EvidenceInbox.group_id == group_filter


@router.get("/api/agents/{agent_id}/evidence")
async def get_agent_evidence(
    agent_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    scope = (EvidenceInbox.agent_id == agent.id, _in_scope(group_filter))
    counts = dict((await db.execute(
        select(EvidenceInbox.status, func.count()).where(*scope).group_by(EvidenceInbox.status)
    )).all())
    oldest_pending = await db.scalar(
        select(func.min(EvidenceInbox.received_at)).where(*scope, EvidenceInbox.status == "pending"))
    dead = (await db.execute(
        select(EvidenceInbox).where(*scope, EvidenceInbox.status == "dead_letter")
        .order_by(EvidenceInbox.received_at).limit(DEAD_LETTER_LIMIT)
    )).scalars().all()
    return {
        "agent_id": str(agent.id),
        **evidence_status(agent.evidence_health, agent.evidence_health_at, datetime.now(timezone.utc)),
        "health": agent.evidence_health,
        "inbox": {
            "pending": counts.get("pending", 0),
            "completed": counts.get("completed", 0),
            "dead_letter": counts.get("dead_letter", 0),
            "oldest_pending_at": oldest_pending.isoformat() if oldest_pending else None,
            # metadata only: payloads stay in the inbox
            "dead_letters": [{
                "receipt_id": str(r.receipt_id), "event_id": str(r.event_id), "failure_count": r.failure_count,
                "last_error": (r.last_error or "")[:500], "received_at": r.received_at.isoformat(),
                "collected_at": r.collected_at.isoformat(),
            } for r in dead],
        },
    }


@router.post("/api/agents/{agent_id}/evidence/{receipt_id}/retry")
async def retry_dead_letter(
    agent_id: UUID,
    receipt_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Put one dead-lettered event back to pending with a fresh attempt count.
    Its retained payload is processed again (detections may repeat)."""
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    row = (await db.execute(
        select(EvidenceInbox).where(EvidenceInbox.receipt_id == receipt_id, EvidenceInbox.agent_id == agent.id,
                                    _in_scope(group_filter)).with_for_update()
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if row.status != "dead_letter":
        raise HTTPException(status_code=409, detail=f"Only dead letters can be retried (status: {row.status})")
    if row.payload is None:
        raise HTTPException(status_code=409, detail="Payload no longer retained")
    now = datetime.now(timezone.utc)
    previous = {"failure_count": row.failure_count, "last_error": (row.last_error or "")[:500]}
    row.status, row.failure_count, row.last_error = "pending", 0, None
    row.next_attempt_at = row.next_dispatch_at = now
    await db.commit()
    background.add_task(audit_log, db, current_user.id, "evidence_retried", "evidence", str(receipt_id),
                        {"agent_id": str(agent.id), "group_id": row.group_id, **previous})
    return {"receipt_id": str(receipt_id), "status": "pending"}
