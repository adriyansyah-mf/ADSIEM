# worker/worker/evidence_inbox.py
"""Delivery for the durable evidence inbox (server-api accepts into it, see
app/services/evidence_inbox.py). The database owns delivery; Redis only
carries references:

- dispatch_once sends `kind=evidence_v2` references for eligible pending rows
  and pushes next_dispatch_at out only after XADD succeeded, so a lost, trimmed
  or duplicated reference is resent later and never loses evidence. It sends
  nothing while the workers are behind (DISPATCH_MAX_BACKLOG unread entries),
  and the resend interval doubles per dispatch: resending every minute into a
  stream the workers could not keep up with filled Redis to maxmemory with
  copies of the same references.
- process_reference locks the row, reads the authoritative payload, runs the
  normal pipeline with a stable document id, and commits completion before the
  consumer acks. A failure is counted in a fresh transaction with capped
  backoff; the 20th dead-letters the row and keeps its payload. Redis being
  down or full is not the event's fault: it is deferred without counting.
- evidence_retention_once drops completed payloads after 7 days (releasing the
  group budget in the same transaction) and completed receipts after 30.
  Pending and dead-letter rows never age out.

Detection is at least once: a crash after indexing repeats rule evaluation,
but the Elasticsearch document id stays the same.
"""
import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from redis import exceptions as redis_errors
from sqlalchemy import delete, func, null, select, update
from sqlalchemy.exc import DBAPIError

from worker.config import (DISPATCH_MAX_BACKLOG, REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY,
                           REDIS_STREAM_MAXLEN)
from worker.database import AsyncSessionLocal
from worker.models import EvidenceGroupUsage, EvidenceInbox
from worker.redis_client import get_redis

log = structlog.get_logger()

EVIDENCE_KIND = "evidence_v2"
DISPATCH_BATCH = 200
REDISPATCH_SECONDS = 60       # a reference not completed by then is sent again...
REDISPATCH_CAP_SECONDS = 1800  # ...doubling per dispatch, up to this
PROCESS_TIMEOUT_SECONDS = 60  # one processing attempt
RETRY_CAP_SECONDS = 60
TRANSIENT_RETRY_SECONDS = 30  # Redis down or full: try again, not counted as a failure
MAX_FAILURES = 20
PAYLOAD_RETENTION = timedelta(days=7)
RECEIPT_RETENTION = timedelta(days=30)
RETENTION_BATCH = 1000
# A reference can arrive while the dispatcher that sent it still holds the row
# lock (it commits right after the pipeline); wait that out before calling it busy.
BUSY_RETRIES = 20
BUSY_WAIT_SECONDS = 0.1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def evidence_event_id(agent_id: uuid.UUID, event_id: uuid.UUID) -> uuid.UUID:
    """Elasticsearch document id and alert event id: the same event from the same
    agent always maps to the same id; another agent's event id never collides."""
    return uuid.uuid5(agent_id, str(event_id))


def _retry_delay(failures: int) -> timedelta:
    return timedelta(seconds=min(2 ** failures, RETRY_CAP_SECONDS))


def redispatch_delay(dispatches: int) -> timedelta:
    """How long a reference gets before it is sent again, given how many were
    already sent for the row: 1, 2, 4... minutes, capped."""
    return timedelta(seconds=min(REDISPATCH_SECONDS * 2 ** min(dispatches, 16), REDISPATCH_CAP_SECONDS))


def is_transient(exc: BaseException) -> bool:
    """Redis unreachable, loading, timing out or at maxmemory, anywhere in the chain."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (redis_errors.ConnectionError, redis_errors.TimeoutError,
                            redis_errors.OutOfMemoryError)):
            return True
        if isinstance(exc, redis_errors.ResponseError) and "maxmemory" in str(exc):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


async def stream_backlog(redis) -> int:
    """Entries in the log stream the workers have not read yet."""
    try:
        groups = await redis.xinfo_groups(REDIS_STREAM_KEY)
    except redis_errors.ResponseError:  # no stream yet
        return 0
    for group in groups:
        if group.get("name") == REDIS_CONSUMER_GROUP and group.get("lag") is not None:
            return int(group["lag"])
    # no group yet, or Redis cannot tell the lag (entries deleted mid-stream): count everything
    return int(await redis.xlen(REDIS_STREAM_KEY))


async def dispatch_once(now: datetime | None = None) -> int:
    """Send references for eligible pending rows. Returns how many were sent."""
    now = now or _now()
    redis = await get_redis()
    try:
        room = DISPATCH_MAX_BACKLOG - await stream_backlog(redis)
    except Exception as exc:  # Redis down: nothing can be sent anyway
        log.warning("evidence_dispatch_redis_failed", rows=0, error=str(exc))
        return 0
    if room <= 0:  # the rows stay due; they go out once the workers caught up
        return 0
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(EvidenceInbox.receipt_id, EvidenceInbox.group_id, EvidenceInbox.hostname,
                   EvidenceInbox.dispatch_count)
            .where(EvidenceInbox.status == "pending",
                   EvidenceInbox.next_dispatch_at <= now,
                   EvidenceInbox.next_attempt_at <= now)
            .order_by(EvidenceInbox.next_dispatch_at)
            .limit(min(DISPATCH_BATCH, room))
            .with_for_update(skip_locked=True)
        )).all()
        if not rows:
            return 0
        pipe = redis.pipeline(transaction=False)
        for row in rows:
            # a trimmed reference is safe: the row is resent
            pipe.xadd(REDIS_STREAM_KEY, {"kind": EVIDENCE_KIND, "receipt_id": str(row.receipt_id),
                                         "group_id": row.group_id, "hostname": row.hostname},
                      maxlen=REDIS_STREAM_MAXLEN, approximate=True)
        try:
            await pipe.execute()
        except Exception as exc:  # Redis down: leave the rows due, retry next round
            await db.rollback()
            log.warning("evidence_dispatch_redis_failed", rows=len(rows), error=str(exc))
            return 0
        by_count: dict[int, list[uuid.UUID]] = {}
        for row in rows:
            by_count.setdefault(row.dispatch_count, []).append(row.receipt_id)
        for dispatches, receipt_ids in sorted(by_count.items()):
            await db.execute(
                update(EvidenceInbox)
                .where(EvidenceInbox.receipt_id.in_(receipt_ids))
                .values(next_dispatch_at=now + redispatch_delay(dispatches),
                        dispatch_count=EvidenceInbox.dispatch_count + 1)
            )
        await db.commit()
    return len(rows)


async def _lock_row(db, receipt_id: uuid.UUID) -> tuple[EvidenceInbox | None, str | None]:
    for _ in range(BUSY_RETRIES):
        row = (await db.execute(
            select(EvidenceInbox).where(EvidenceInbox.receipt_id == receipt_id)
            .with_for_update(skip_locked=True).execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if row is not None:
            return row, None
        exists = await db.scalar(select(func.count()).where(EvidenceInbox.receipt_id == receipt_id))
        if not exists:
            return None, "missing"
        await asyncio.sleep(BUSY_WAIT_SECONDS)
    return None, "busy"


async def process_reference(receipt_id: uuid.UUID, state: dict, now: datetime | None = None) -> str:
    """Process one inbox reference. Returns completed, duplicate, busy, deferred,
    dead_letter or missing; every outcome is safe to ack."""
    from worker import consumer  # consumer routes references here

    now = now or _now()
    async with AsyncSessionLocal() as db:
        row, outcome = await _lock_row(db, receipt_id)
        if row is None:
            return outcome
        if row.status == "completed":
            return "duplicate"
        if row.status == "dead_letter":
            return "dead_letter"
        if row.payload is None:
            return "missing"
        if row.next_attempt_at > now:
            return "deferred"

        envelope = json.loads(row.payload)
        data = {
            "agent_id": str(row.agent_id),
            "log_type": envelope.get("log_type", ""),
            "raw_message": envelope.get("raw_message", ""),
            "location": envelope.get("location", ""),
            "hostname": row.hostname,  # snapshot at acceptance, like the legacy stream entry
            "group_id": row.group_id,
            "received_at": row.collected_at.isoformat(),  # original collection time
        }
        try:
            await asyncio.wait_for(
                consumer.process_message(data, state["dec_engine"], state["sig_engine"],
                                         event_id=evidence_event_id(row.agent_id, row.event_id)),
                PROCESS_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            await db.rollback()  # shutdown: not a failed attempt; the row stays due
            raise
        except Exception as exc:
            await db.rollback()
            return await _record_failure(receipt_id, exc)
        row.status = "completed"
        row.completed_at = _now()
        row.last_error = None
        await db.commit()
    return "completed"


async def _record_failure(receipt_id: uuid.UUID, exc: BaseException) -> str:
    async with AsyncSessionLocal() as db:
        row = (await db.execute(
            select(EvidenceInbox).where(EvidenceInbox.receipt_id == receipt_id).with_for_update()
        )).scalar_one_or_none()
        if row is None:
            return "missing"
        if row.status != "pending":  # another worker finished it meanwhile
            return "duplicate" if row.status == "completed" else row.status
        row.last_error = f"{type(exc).__name__}: {exc}"[:1000]
        if is_transient(exc):
            row.next_attempt_at = _now() + timedelta(seconds=TRANSIENT_RETRY_SECONDS)
            row.next_dispatch_at = max(row.next_dispatch_at, row.next_attempt_at)
            await db.commit()
            log.warning("evidence_processing_deferred", receipt_id=str(receipt_id), error=row.last_error)
            return "deferred"
        row.failure_count += 1
        if row.failure_count >= MAX_FAILURES:
            row.status = "dead_letter"
            outcome = "dead_letter"
        else:
            row.next_attempt_at = _now() + _retry_delay(row.failure_count)
            row.next_dispatch_at = max(row.next_dispatch_at, row.next_attempt_at)
            outcome = "deferred"
        await db.commit()
    log.warning("evidence_processing_failed", receipt_id=str(receipt_id), outcome=outcome,
                failures=row.failure_count, error=row.last_error)
    return outcome


async def evidence_retention_once(now: datetime | None = None) -> int:
    """Release completed payloads after 7 days (and their group budget), delete
    completed receipts after 30. Returns payloads released plus receipts deleted."""
    now = now or _now()
    async with AsyncSessionLocal() as db:
        due = (await db.execute(
            select(EvidenceInbox.receipt_id, EvidenceInbox.group_id, EvidenceInbox.payload_bytes)
            .where(EvidenceInbox.status == "completed",
                   EvidenceInbox.completed_at < now - PAYLOAD_RETENTION,
                   EvidenceInbox.payload.isnot(None))
            .limit(RETENTION_BATCH)
            .with_for_update(skip_locked=True)
        )).all()
        released: dict[str, int] = {}
        for row in due:
            released[row.group_id] = released.get(row.group_id, 0) + row.payload_bytes
        if due:
            await db.execute(update(EvidenceInbox)
                             .where(EvidenceInbox.receipt_id.in_([r.receipt_id for r in due]))
                             .values(payload=null()))
            for group_id, payload_bytes in sorted(released.items()):  # stable lock order
                await db.execute(update(EvidenceGroupUsage)
                                 .where(EvidenceGroupUsage.group_id == group_id)
                                 .values(payload_bytes=func.greatest(
                                     EvidenceGroupUsage.payload_bytes - payload_bytes, 0)))
        await db.flush()
        expired = select(EvidenceInbox.receipt_id).where(
            EvidenceInbox.status == "completed",
            EvidenceInbox.completed_at < now - RECEIPT_RETENTION,
            EvidenceInbox.payload.is_(None),
        ).limit(RETENTION_BATCH).with_for_update(skip_locked=True)
        deleted = (await db.execute(
            delete(EvidenceInbox).where(EvidenceInbox.receipt_id.in_(expired.scalar_subquery()))
        )).rowcount or 0
        await db.commit()
    if due or deleted:
        log.info("evidence_retention", payloads_released=len(due), receipts_deleted=deleted)
    return len(due) + deleted


def _inbox_missing(exc: Exception) -> bool:
    # server-api creates the tables at startup; the worker may come up first
    return isinstance(exc, DBAPIError) and "evidence_inbox" in str(exc) and "does not exist" in str(exc)


async def evidence_dispatch_loop() -> None:
    while True:
        try:
            sent = await dispatch_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if _inbox_missing(exc):
                await asyncio.sleep(60)
                continue
            log.error("evidence_dispatch_error", error=str(exc))
            await asyncio.sleep(5)
            continue
        await asyncio.sleep(0 if sent >= DISPATCH_BATCH else 1)


async def evidence_retention_loop() -> None:
    while True:
        try:
            # drain a backlog in batches, then wait for the next hour
            while await evidence_retention_once() >= RETENTION_BATCH:
                pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not _inbox_missing(exc):
                log.error("evidence_retention_error", error=str(exc))
        await asyncio.sleep(3600)
