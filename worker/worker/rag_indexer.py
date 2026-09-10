"""Background loop: index resolved/closed cases and analyst feedback that do
not have embeddings yet.

Two cadences, deliberately separate. The Redis queues carry "index this now"
requests and are drained every few seconds. The batch sweep is a slow
reconciliation that catches anything the queues missed, and runs hourly.
Tying both to one interval, as this loop originally did, made the "immediate"
queues up to an hour late.
"""
import asyncio
import time
import structlog
from sqlalchemy import text
from worker.database import AsyncSessionLocal
from worker.rag import index_case, index_sop_document, index_feedback

log = structlog.get_logger()
INDEX_INTERVAL = 3600  # batch reconciliation sweep, once per hour
QUEUE_DRAIN_INTERVAL = 15  # an "immediate" queue is only immediate if drained often
REINDEX_QUEUE = "siem:rag:reindex"  # Redis list for immediate re-index requests
FEEDBACK_REINDEX_QUEUE = "siem:rag:feedback-reindex"


async def rag_index_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(60)  # let server start first
    redis = await get_redis()
    last_batch: float | None = None  # None forces a sweep on the first pass
    while True:
        try:
            # ── Drain immediate re-index queue first ──────────────────────────
            while True:
                item = await redis.lpop(REINDEX_QUEUE)
                if not item:
                    break
                case_id = item.decode() if isinstance(item, bytes) else item
                try:
                    async with AsyncSessionLocal() as db:
                        row = (await db.execute(text("""
                            SELECT c.id::text, c.title, c.description,
                                   COALESCE(c.ioc_data->>'verdict', c.status) AS verdict,
                                   c.group_id
                            FROM cases c
                            WHERE c.id = CAST(:case_id AS uuid)
                        """), {"case_id": case_id})).mappings().first()
                    if row:
                        await index_case(
                            case_id=row["id"],
                            title=row["title"],
                            description=row["description"],
                            verdict=row["verdict"],
                            group_id=row["group_id"],
                        )
                        log.info("rag_reindex_immediate", case_id=case_id, verdict=row["verdict"])
                except Exception as e:
                    log.error("rag_reindex_item_error", case_id=case_id, error=str(e))

            # ── Drain feedback re-index queue ──────────────────────────────────
            while True:
                item = await redis.lpop(FEEDBACK_REINDEX_QUEUE)
                if not item:
                    break
                feedback_id = item.decode() if isinstance(item, bytes) else item
                try:
                    async with AsyncSessionLocal() as db:
                        row = (await db.execute(text("""
                            SELECT id::text, context_text, rating, group_id
                            FROM ai_feedback
                            WHERE id = CAST(:feedback_id AS uuid)
                        """), {"feedback_id": feedback_id})).mappings().first()
                    if row:
                        await index_feedback(
                            feedback_id=row["id"],
                            context_text=row["context_text"],
                            rating=row["rating"],
                            group_id=row["group_id"],
                        )
                        log.info("rag_feedback_reindex_immediate", feedback_id=feedback_id)
                except Exception as e:
                    log.error("rag_feedback_reindex_item_error", feedback_id=feedback_id, error=str(e))

            now = time.monotonic()
            if last_batch is None or now - last_batch >= INDEX_INTERVAL:
                last_batch = now
                await _batch_reconcile()
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("rag_indexer_error", error=str(e))

        await asyncio.sleep(QUEUE_DRAIN_INTERVAL)


async def _batch_reconcile() -> None:
    """Index anything the immediate queues missed.

    Without this, a single missed enqueue orphans a record permanently: the
    queue entry is consumed once and never regenerated. Cases have always had
    this safety net; analyst feedback did not, which is why eight analyst
    corrections sat unindexed and never reached a triage prompt.
    """
    async with AsyncSessionLocal() as db:
        case_rows = (await db.execute(text("""
            SELECT c.id::text, c.title, c.description,
                   COALESCE(c.ioc_data->>'verdict', c.status) AS verdict,
                   c.group_id
            FROM cases c
            LEFT JOIN case_embeddings ce ON ce.case_id = c.id
            WHERE c.status IN ('resolved', 'closed')
              AND ce.case_id IS NULL
            ORDER BY c.updated_at DESC
            LIMIT 100
        """))).mappings().all()

    if case_rows:
        log.info("rag_indexer_batch", count=len(case_rows))
        for row in case_rows:
            await index_case(
                case_id=row["id"],
                title=row["title"],
                description=row["description"],
                verdict=row["verdict"],
                group_id=row["group_id"],
            )

    async with AsyncSessionLocal() as db:
        feedback_rows = (await db.execute(text("""
            SELECT f.id::text, f.context_text, f.rating, f.group_id
            FROM ai_feedback f
            LEFT JOIN feedback_embeddings fe ON fe.feedback_id = f.id
            WHERE fe.feedback_id IS NULL
            ORDER BY f.created_at DESC
            LIMIT 50
        """))).mappings().all()

    if feedback_rows:
        log.info("rag_feedback_batch", count=len(feedback_rows))
        for row in feedback_rows:
            await index_feedback(
                feedback_id=row["id"],
                context_text=row["context_text"],
                rating=row["rating"],
                group_id=row["group_id"],
            )


SOP_INDEX_INTERVAL = 60  # poll every 60s for pending documents


async def sop_index_loop() -> None:
    await asyncio.sleep(90)  # stagger startup after rag_index_loop
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT id::text, group_id, raw_text
                    FROM sop_documents
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT 10
                """))).mappings().all()

            for row in rows:
                await index_sop_document(
                    document_id=row["id"],
                    group_id=row["group_id"],
                    raw_text=row["raw_text"],
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("sop_indexer_error", error=str(e))

        await asyncio.sleep(SOP_INDEX_INTERVAL)
