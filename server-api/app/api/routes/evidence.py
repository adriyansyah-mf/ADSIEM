# server-api/app/api/routes/evidence.py
"""Durable evidence delivery per agent: the last health snapshot the agent
reported, the server inbox for it, and operator retry of dead letters."""
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select, true, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.core.config import settings
from app.models.models import Agent, EvidenceGroupUsage, EvidenceInbox, User
from app.services.audit import audit_log
from app.services.evidence_status import evidence_status

router = APIRouter(tags=["evidence"])

DEAD_LETTER_LIMIT = 50


TOP_HOSTS = 3


@router.get("/api/evidence/usage")
async def evidence_usage(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
):
    """Evidence storage per group against the budget that turns new evidence
    away with 429 evidence_group_capacity once it is full (evidence_inbox)."""
    usage_q = select(EvidenceGroupUsage.group_id, EvidenceGroupUsage.payload_bytes)
    hosts_q = (select(EvidenceInbox.group_id, EvidenceInbox.hostname, func.sum(EvidenceInbox.payload_bytes).label("bytes"))
               .group_by(EvidenceInbox.group_id, EvidenceInbox.hostname))
    if group_filter is not None:
        usage_q = usage_q.where(EvidenceGroupUsage.group_id == group_filter)
        hosts_q = hosts_q.where(EvidenceInbox.group_id == group_filter)
    budget = settings.EVIDENCE_GROUP_BUDGET_BYTES
    top: dict[str, list[dict]] = {}
    for group_id, hostname, used in (await db.execute(hosts_q)).all():
        top.setdefault(group_id, []).append({"hostname": hostname, "payload_bytes": int(used or 0)})
    groups = []
    for group_id, used in (await db.execute(usage_q.order_by(EvidenceGroupUsage.payload_bytes.desc()))).all():
        hosts = sorted(top.get(group_id, []), key=lambda h: h["payload_bytes"], reverse=True)[:TOP_HOSTS]
        groups.append({"group_id": group_id, "payload_bytes": int(used), "percent": round(min(used / budget, 1.0) * 100, 1),
                       "full": used >= budget, "top_hosts": hosts})
    return {"budget_bytes": budget, "groups": groups}


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


@router.post("/api/agents/{agent_id}/evidence/retry-dead-letters")
async def retry_all_dead_letters(
    agent_id: UUID,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Put every dead-lettered event of the agent that still has its payload
    back to pending with a fresh attempt count, e.g. after an outage."""
    agent = await fetch_scoped(db, Agent, agent_id, group_filter, detail="Agent not found")
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(EvidenceInbox)
        .where(EvidenceInbox.agent_id == agent.id, _in_scope(group_filter),
               EvidenceInbox.status == "dead_letter", EvidenceInbox.payload.isnot(None))
        .values(status="pending", failure_count=0, last_error=None, next_attempt_at=now, next_dispatch_at=now)
    )
    await db.commit()
    retried = result.rowcount or 0
    if retried:
        background.add_task(audit_log, db, current_user.id, "evidence_retried_all", "agent", str(agent.id),
                            {"retried": retried})
    return {"retried": retried}


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
