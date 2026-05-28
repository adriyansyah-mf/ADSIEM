"""Background loop: index resolved/closed cases that don't have embeddings yet."""
import asyncio
import structlog
from sqlalchemy import text
from worker.database import AsyncSessionLocal
from worker.rag import index_case

log = structlog.get_logger()
INDEX_INTERVAL = 3600  # once per hour


async def rag_index_loop() -> None:
    await asyncio.sleep(60)  # let server start first
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT c.id::text, c.title, c.description, c.status, c.group_id
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
                        verdict=row["status"],
                        group_id=row["group_id"],
                    )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("rag_indexer_error", error=str(e))

        await asyncio.sleep(INDEX_INTERVAL)
