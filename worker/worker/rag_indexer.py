"""Background loop: index resolved/closed cases that don't have embeddings yet."""
import asyncio
import structlog
from sqlalchemy import text
from worker.database import AsyncSessionLocal
from worker.rag import index_case, index_sop_document

log = structlog.get_logger()
INDEX_INTERVAL = 3600  # once per hour
REINDEX_QUEUE = "siem:rag:reindex"  # Redis list for immediate re-index requests


async def rag_index_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(60)  # let server start first
    redis = await get_redis()
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
                            WHERE c.id = :case_id::uuid
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

            # ── Batch poll for unindexed resolved/closed cases ────────────────
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
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

            if rows:
                log.info("rag_indexer_batch", count=len(rows))
                for row in rows:
                    await index_case(
                        case_id=row["id"],
                        title=row["title"],
                        description=row["description"],
                        verdict=row["verdict"],
                        group_id=row["group_id"],
                    )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("rag_indexer_error", error=str(e))

        await asyncio.sleep(INDEX_INTERVAL)


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
