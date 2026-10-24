"""Durable acceptance only. Redis dispatch belongs to the inbox consumer."""
import json
from datetime import datetime
from typing import Literal

import structlog
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Agent, EvidenceGroupUsage, EvidenceInbox
from app.schemas.schemas import EvidenceEnvelope, EvidenceReceipt

log = structlog.get_logger()
MAX_EVENT_BYTES = 1 << 20
MAX_REQUEST_BYTES = 2 << 20


async def check_evidence_durability(db: AsyncSession) -> bool:
    """Fresh WAL and schema checks, isolated so a missing schema cannot break heartbeat."""
    try:
        async with db.begin_nested():
            for setting in ("fsync", "full_page_writes"):
                if (await db.execute(text(f"SHOW {setting}"))).scalar_one() != "on":
                    return False
            # Resolve using this connection's search_path. Unlogged and temporary
            # relations do not have the durable WAL semantics promised by a receipt.
            persisted = await db.scalar(text("""
                SELECT count(*) = 2 FROM pg_class
                WHERE oid IN (to_regclass('evidence_inbox'), to_regclass('evidence_group_usage'))
                  AND relpersistence = 'p' AND relkind = 'r'
            """))
            if not persisted:
                return False
            # Verify every mapped column before advertising a partially migrated schema.
            await db.execute(select(EvidenceInbox).limit(0))
            await db.execute(select(EvidenceGroupUsage).limit(0))
            constraints = await db.scalar(text("""
                SELECT count(*) = 3 FROM pg_constraint
                WHERE (conrelid = 'evidence_inbox'::regclass AND
                       ((contype = 'p' AND pg_get_constraintdef(oid) = 'PRIMARY KEY (receipt_id)') OR
                        (contype = 'u' AND pg_get_constraintdef(oid) = 'UNIQUE (agent_id, event_id)')))
                   OR (conrelid = 'evidence_group_usage'::regclass AND contype = 'p'
                       AND pg_get_constraintdef(oid) = 'PRIMARY KEY (group_id)')
            """))
            return bool(constraints)
    except (SQLAlchemyError, OSError):
        log.warning("evidence_durability_unavailable")
        return False


def _receipt(row: EvidenceInbox, status: Literal["accepted", "duplicate"]) -> EvidenceReceipt:
    return EvidenceReceipt(event_id=row.event_id, receipt_id=row.receipt_id, status=status)


async def accept_evidence(db: AsyncSession, agent: Agent, body: EvidenceEnvelope) -> EvidenceReceipt:
    """Commit inbox + usage together, and return a receipt only after durable commit.

    The agent row lock serializes retries even across concurrent group moves;
    the group usage row lock enforces the capacity budget across API replicas.
    No foreign key to Agent exists: deletion cannot destroy retained receipts.
    """
    try:
        if not settings.EVIDENCE_INGEST_ENABLED:
            raise HTTPException(status_code=503, detail="evidence_ingest_disabled")
        if body.agent_id != agent.id:
            raise HTTPException(status_code=403, detail="agent_identity_mismatch")
        if body.encoded_size > MAX_EVENT_BYTES:
            raise HTTPException(status_code=413, detail="evidence_event_too_large")
        await db.execute(text("SET LOCAL synchronous_commit = on"))
        if not await check_evidence_durability(db):
            raise HTTPException(status_code=503, detail="evidence_durability_unavailable")
        current_agent = (await db.execute(
            select(Agent).where(Agent.id == agent.id).with_for_update().execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if current_agent is None:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        if not current_agent.approved:
            raise HTTPException(status_code=403, detail="pending_approval", headers={"Retry-After": "60"})
        digest = body.digest()
        duplicate_query = select(EvidenceInbox).where(
            EvidenceInbox.agent_id == current_agent.id, EvidenceInbox.event_id == body.event_id,
        )
        existing = (await db.execute(duplicate_query)).scalar_one_or_none()
        if existing is not None:
            if existing.payload_digest != digest:
                raise HTTPException(status_code=409, detail="evidence_identity_conflict")
            receipt = _receipt(existing, "duplicate")
            await db.commit()
            return receipt

        await db.execute(insert(EvidenceGroupUsage).values(
            group_id=current_agent.group_id, payload_bytes=0,
        ).on_conflict_do_nothing(index_elements=[EvidenceGroupUsage.group_id]))
        usage = (await db.execute(select(EvidenceGroupUsage).where(
            EvidenceGroupUsage.group_id == current_agent.group_id,
        ).with_for_update())).scalar_one()
        # Charge the stored JSONB scalar's serialized UTF-8 bytes, including outer
        # string escaping (not merely the smaller inner envelope or wire payload).
        payload = body.canonical_json()
        payload_bytes = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        if usage.payload_bytes + payload_bytes > settings.EVIDENCE_GROUP_BUDGET_BYTES:
            # The agent lock ensures the preceding lookup cannot miss a concurrent
            # duplicate, including when that receipt belongs to the agent's old group.
            raise HTTPException(status_code=429, detail="evidence_group_capacity", headers={"Retry-After": "60"})
        usage.payload_bytes += payload_bytes
        row = EvidenceInbox(
            agent_id=current_agent.id, event_id=body.event_id,
            group_id=current_agent.group_id, hostname=current_agent.hostname,
            payload_digest=digest, payload=payload, payload_bytes=payload_bytes,
            collected_at=datetime.fromisoformat(body.collected_at.replace("Z", "+00:00")),
        )
        db.add(row)
        await db.flush()
        receipt = _receipt(row, "accepted")
        await db.commit()
        return receipt
    except HTTPException:
        await db.rollback()
        raise
    except (SQLAlchemyError, OSError) as exc:
        await db.rollback()
        log.warning("evidence_accept_failed", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="evidence_storage_unavailable") from exc
