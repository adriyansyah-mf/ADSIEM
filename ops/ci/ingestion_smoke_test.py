"""CI ingestion smoke/regression gate.

This is deliberately NOT a capacity/load benchmark (see
reports/sustained-ingestion-baseline-2026-09-06.md for that manual,
persistent-producer-based work, which stays out of CI). It exercises the
real decode -> normalize -> index-to-Elasticsearch hot path
(`worker.consumer.process_message`) directly, in-process, against a batch of
synthetic events, and fails the build if that path breaks outright or
regresses to a crawl -- a regression gate, not a performance SLA.

Run from the worker/ directory with worker's dependencies installed and
DATABASE_URL / REDIS_URL / ELASTICSEARCH_URL pointed at real services:

    cd worker && python ../ops/ci/ingestion_smoke_test.py
"""
from __future__ import annotations

import asyncio
import sys
import time
import uuid
from datetime import datetime, timezone

EVENT_COUNT = 200
MAX_SECONDS = 30.0  # generous: this guards against a stall/crash, not a speed target


async def _refresh_index() -> None:
    """Force Elasticsearch to make just-indexed documents visible to
    `_count`/`_search` immediately, instead of waiting out the default ~1s
    refresh interval -- without this, a `count_by_query` run right after a
    tight indexing loop undercounts and looks like data loss when none
    occurred (every document is durably written either way)."""
    import httpx
    from worker.config import ELASTICSEARCH_URL
    async with httpx.AsyncClient(base_url=ELASTICSEARCH_URL, timeout=15) as client:
        await client.post("/logs/_refresh")


async def main() -> int:
    from worker.consumer import load_engines, process_message
    from worker.database import AsyncSessionLocal
    from worker.es_client import count_by_query, ensure_index

    await ensure_index()

    marker = f"ci-smoke-{uuid.uuid4()}"
    before = await count_by_query({"term": {"log_type": marker}})
    if before != 0:
        print(f"FAIL: marker {marker!r} unexpectedly pre-existed ({before} docs)")
        return 1

    async with AsyncSessionLocal() as db:
        dec_engine, sig_engine = await load_engines(db)

    start = time.monotonic()
    for i in range(EVENT_COUNT):
        await process_message(
            {
                "agent_id": "",
                "log_type": marker,
                "raw_message": f"ci smoke test event {i}",
                "received_at": datetime.now(timezone.utc).isoformat(),
                "hostname": "ci-runner",
                "group_id": "ci-smoke",
            },
            dec_engine,
            sig_engine,
        )
    elapsed = time.monotonic() - start

    await _refresh_index()
    after = await count_by_query({"term": {"log_type": marker}})
    indexed = after - before

    print(f"processed {EVENT_COUNT} events in {elapsed:.2f}s ({EVENT_COUNT / elapsed:.1f} events/sec)")
    print(f"indexed in Elasticsearch: {indexed}/{EVENT_COUNT}")

    ok = True
    if indexed != EVENT_COUNT:
        print(f"FAIL: expected {EVENT_COUNT} indexed documents, found {indexed}")
        ok = False
    if elapsed > MAX_SECONDS:
        print(f"FAIL: took {elapsed:.2f}s, over the {MAX_SECONDS}s regression threshold")
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
