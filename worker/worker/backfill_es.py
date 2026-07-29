# worker/worker/backfill_es.py
"""One-off migration: copy existing Postgres events+raw_logs rows into
Elasticsearch, preserving events.id as the ES document _id so alerts.event_id
still resolves correctly after the raw_logs/events tables are dropped.

Run once per environment, BEFORE dropping the Postgres tables:
    docker compose exec worker python -m worker.backfill_es
"""
import asyncio
import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal
from worker.es_client import index_log, ensure_index

log = structlog.get_logger()

_BATCH_SIZE = 500

_QUERY = text("""
    SELECT e.id, e.agent_id, e.group_id, e.decoded_fields, e.event_category,
           e.event_action, e.source_ip, e.user_name, e.created_at,
           r.log_type, r.raw_message
    FROM events e
    LEFT JOIN raw_logs r ON r.id = e.raw_log_id
    ORDER BY e.created_at
    LIMIT :limit OFFSET :offset
""")


async def run() -> None:
    await ensure_index()
    offset = 0
    total = 0
    async with AsyncSessionLocal() as db:
        while True:
            rows = (await db.execute(_QUERY, {"limit": _BATCH_SIZE, "offset": offset})).all()
            if not rows:
                break
            for row in rows:
                await index_log(str(row.id), {
                    "agent_id": str(row.agent_id) if row.agent_id else None,
                    "group_id": row.group_id,
                    "log_type": row.log_type,
                    "raw_message": row.raw_message or "",
                    "decoded_fields": row.decoded_fields or {},
                    "event_category": row.event_category,
                    "event_action": row.event_action,
                    "source_ip": row.source_ip,
                    "user_name": row.user_name,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                })
            total += len(rows)
            offset += _BATCH_SIZE
            log.info("backfill_progress", indexed=total)

    log.info("backfill_done", total=total)


if __name__ == "__main__":
    asyncio.run(run())
