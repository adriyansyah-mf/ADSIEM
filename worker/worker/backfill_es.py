# worker/worker/backfill_es.py
"""One-off migration: copy existing Postgres events+raw_logs rows into
Elasticsearch, preserving events.id as the ES document _id so alerts.event_id
still resolves correctly after the raw_logs/events tables are dropped.

Uses the bulk API + keyset pagination on e.id — plain OFFSET pagination
falls over at production scale (millions of rows), since Postgres has to
scan and discard every skipped row on each page.

Run once per environment, BEFORE dropping the Postgres tables:
    docker compose exec worker python -m worker.backfill_es
"""
import asyncio
import time
import uuid
import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal
from worker.es_client import bulk_index, ensure_index

log = structlog.get_logger()

_BATCH_SIZE = 2000

_QUERY = text("""
    SELECT e.id, e.agent_id, e.group_id, e.decoded_fields, e.event_category,
           e.event_action, e.source_ip, e.user_name, e.created_at,
           r.log_type, r.raw_message
    FROM events e
    LEFT JOIN raw_logs r ON r.id = e.raw_log_id
    WHERE e.id > :after_id
    ORDER BY e.id
    LIMIT :limit
""")


async def run() -> None:
    await ensure_index()
    after_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    total = 0
    total_errors = 0
    started = time.monotonic()

    async with AsyncSessionLocal() as db:
        while True:
            rows = (await db.execute(_QUERY, {"after_id": after_id, "limit": _BATCH_SIZE})).all()
            if not rows:
                break

            docs = [(
                str(row.id),
                {
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
                },
            ) for row in rows]

            total_errors += await bulk_index(docs)
            total += len(rows)
            after_id = rows[-1].id

            elapsed = time.monotonic() - started
            log.info("backfill_progress", indexed=total, errors=total_errors,
                     rate_per_sec=round(total / elapsed, 1) if elapsed > 0 else 0)

    log.info("backfill_done", total=total, errors=total_errors,
             elapsed_sec=round(time.monotonic() - started, 1))


if __name__ == "__main__":
    asyncio.run(run())
