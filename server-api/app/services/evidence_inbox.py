"""Durable acceptance only. Redis dispatch belongs to the inbox consumer."""
import json
import uuid
from datetime import datetime
from typing import Literal

from pydantic import ValidationError

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
MAX_BATCH_EVENTS = 500
MAX_BATCH_REQUEST_BYTES = 4 << 20


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


def _rejected(event_id, code: int, detail: str) -> dict:
    return {"event_id": event_id, "status": "rejected", "code": code, "detail": detail}


async def accept_evidence_batch(db: AsyncSession, agent: Agent, items: list) -> list[dict]:
    """accept_evidence for up to MAX_BATCH_EVENTS raw envelopes in one
    transaction, so a backlog is not one synchronous commit per event.

    Returns one result per item, in order: accepted / duplicate (with the
    original receipt) / rejected (409 changed payload, 413 too large, 422
    invalid; never with payload content) / retry (429 once the group budget is
    full; every later new item too, so order is kept). Request-level problems
    raise as in accept_evidence. Receipts exist only after the commit."""
    try:
        if not settings.EVIDENCE_INGEST_ENABLED:
            raise HTTPException(status_code=503, detail="evidence_ingest_disabled")
        parsed: list[tuple[EvidenceEnvelope | None, object]] = []
        for item in items:
            try:
                envelope = EvidenceEnvelope.model_validate(item)
            except ValidationError:
                parsed.append((None, item))
                continue
            if envelope.agent_id != agent.id:
                raise HTTPException(status_code=403, detail="agent_identity_mismatch")
            parsed.append((envelope, item))
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

        event_ids = [e.event_id for e, _ in parsed if e is not None]
        known: dict = {}  # event_id -> (digest, receipt_id), stored or earlier in this batch
        if event_ids:
            for row in (await db.execute(select(EvidenceInbox).where(
                EvidenceInbox.agent_id == current_agent.id, EvidenceInbox.event_id.in_(event_ids),
            ))).scalars():
                known[row.event_id] = (row.payload_digest, row.receipt_id)
        await db.execute(insert(EvidenceGroupUsage).values(
            group_id=current_agent.group_id, payload_bytes=0,
        ).on_conflict_do_nothing(index_elements=[EvidenceGroupUsage.group_id]))
        usage = (await db.execute(select(EvidenceGroupUsage).where(
            EvidenceGroupUsage.group_id == current_agent.group_id,
        ).with_for_update())).scalar_one()

        results: list[dict] = []
        budget_full = False
        for envelope, raw in parsed:
            if envelope is None:
                raw_id = raw.get("event_id") if isinstance(raw, dict) else None
                results.append(_rejected(raw_id if isinstance(raw_id, str) else None, 422, "invalid_evidence_envelope"))
                continue
            event_id = str(envelope.event_id)
            if envelope.encoded_size > MAX_EVENT_BYTES:
                results.append(_rejected(event_id, 413, "evidence_event_too_large"))
                continue
            digest = envelope.digest()
            if envelope.event_id in known:
                prior_digest, receipt_id = known[envelope.event_id]
                results.append(_rejected(event_id, 409, "evidence_identity_conflict") if prior_digest != digest
                               else {"event_id": event_id, "status": "duplicate", "receipt_id": str(receipt_id)})
                continue
            payload = envelope.canonical_json()
            payload_bytes = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            if budget_full or usage.payload_bytes + payload_bytes > settings.EVIDENCE_GROUP_BUDGET_BYTES:
                budget_full = True
                results.append({"event_id": event_id, "status": "retry", "code": 429, "detail": "evidence_group_capacity"})
                continue
            usage.payload_bytes += payload_bytes
            row = EvidenceInbox(
                receipt_id=uuid.uuid4(), agent_id=current_agent.id, event_id=envelope.event_id,
                group_id=current_agent.group_id, hostname=current_agent.hostname,
                payload_digest=digest, payload=payload, payload_bytes=payload_bytes,
                collected_at=datetime.fromisoformat(envelope.collected_at.replace("Z", "+00:00")),
            )
            db.add(row)
            known[envelope.event_id] = (digest, row.receipt_id)
            results.append({"event_id": event_id, "status": "accepted", "receipt_id": str(row.receipt_id)})
        await db.flush()
        await db.commit()
        return results
    except HTTPException:
        await db.rollback()
        raise
    except (SQLAlchemyError, OSError) as exc:
        await db.rollback()
        log.warning("evidence_batch_accept_failed", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="evidence_storage_unavailable") from exc
