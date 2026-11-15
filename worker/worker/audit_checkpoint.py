"""Copy the newest link of the audit chain to Elasticsearch every few minutes
(server-api/app/services/audit_chain.py).

Deleting the newest audit rows does not break the chain itself, so the
chain alone cannot show it. With the newest (seq, hash) also kept in a second
store, the verifier notices when the database no longer holds that row, or
holds a different one. Documents are only ever added, one per new chain
head; the index keeps a history of heads."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import structlog
from sqlalchemy import text

from worker import es_client
from worker.database import AsyncSessionLocal

log = structlog.get_logger()

INDEX = "audit_checkpoints"
INTERVAL = 300
MAPPING = {"mappings": {"properties": {
    "seq": {"type": "long"}, "hash": {"type": "keyword"}, "recorded_at": {"type": "date"},
}}}


async def chain_head(db) -> tuple[int, str] | None:
    row = (await db.execute(text(
        "SELECT seq, hash FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1"))).first()
    return (int(row[0]), row[1]) if row else None


async def record(client: httpx.AsyncClient, seq: int, digest: str) -> None:
    if (await client.head(f"/{INDEX}")).status_code == 404:
        await client.put(f"/{INDEX}", json=MAPPING)
    # the document id is the seq, so a head is written once; op_type=create refuses to overwrite
    resp = await client.put(f"/{INDEX}/_doc/{seq}", params={"op_type": "create"},
                            json={"seq": seq, "hash": digest, "recorded_at": datetime.now(timezone.utc).isoformat()})
    if resp.status_code not in (200, 201, 409):
        resp.raise_for_status()


async def audit_checkpoint_loop() -> None:
    await asyncio.sleep(60)
    last = None
    while True:
        try:
            async with AsyncSessionLocal() as db:
                head = await chain_head(db)
            if head and head != last:
                await record(es_client._get_client(), *head)
                last = head
        except Exception as exc:  # noqa: BLE001 — an older schema has no seq yet, or ES is down
            log.warning("audit_checkpoint_failed", error=str(exc))
        await asyncio.sleep(INTERVAL)
