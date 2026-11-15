"""Keep Elasticsearch out of its flood stage.

Age-based retention (maintenance.py) assumes the disk is big enough for the
retention window. When it is not, Elasticsearch reaches its flood-stage
watermark (95% by default), marks the logs index read-only, and ingest
stops without an error anyone sees. Hourly, this guard checks disk usage on
the data nodes. Above `es_disk_guard_percent`, it deletes the oldest day of
logs and expunges the deleted documents (a delete only marks them; the disk
is freed when segments merge). It repeats, a few days per run at most, but
never inside the newest `es_disk_guard_keep_days`. Each step is reported as
a siem_agent health event, so it shows up as an alert.

Long operations run as Elasticsearch tasks (wait_for_completion=false) and
are polled: deleting a day of logs takes far longer than an HTTP timeout."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import httpx
import structlog

from worker import es_client
from worker.settings_cache import get_setting

log = structlog.get_logger()

RUN_INTERVAL = 3600
MAX_DAYS_PER_RUN = 3
TASK_POLL_SECONDS = 5.0
TASK_MAX_SECONDS = 3600.0


async def run_task(client: httpx.AsyncClient, path: str, *, params: dict | None = None, json: dict | None = None,
                   poll: float | None = None, max_wait: float | None = None) -> dict:
    """POST path as a background Elasticsearch task and wait for its response."""
    poll = TASK_POLL_SECONDS if poll is None else poll
    max_wait = TASK_MAX_SECONDS if max_wait is None else max_wait
    resp = await client.post(path, params={**(params or {}), "wait_for_completion": "false"}, json=json)
    resp.raise_for_status()
    body = resp.json()
    task = body.get("task")
    if not task:  # an operation that finished at once
        return body
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        await asyncio.sleep(poll)
        status = await client.get(f"/_tasks/{task}")
        status.raise_for_status()
        data = status.json()
        if data.get("completed"):
            if data.get("error"):
                raise RuntimeError(f"elasticsearch task {task} failed: {data['error']}")
            return data.get("response") or {}
    raise TimeoutError(f"elasticsearch task {task} still running after {max_wait:.0f}s")


async def disk_percent(client: httpx.AsyncClient) -> float | None:
    """The fullest data node's disk usage in percent (None when unknown)."""
    resp = await client.get("/_cat/allocation", params={"format": "json", "h": "node,disk.percent"})
    resp.raise_for_status()
    values = []
    for row in resp.json():
        try:
            values.append(float(row.get("disk.percent")))
        except (TypeError, ValueError):
            continue  # the UNASSIGNED row has no disk
    return max(values) if values else None


async def oldest_log(client: httpx.AsyncClient) -> datetime | None:
    resp = await client.post(f"/{es_client.LOGS_INDEX}/_search",
                             json={"size": 0, "aggs": {"oldest": {"min": {"field": "created_at"}}}})
    resp.raise_for_status()
    value = resp.json().get("aggregations", {}).get("oldest", {}).get("value")
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc) if value is not None else None


async def delete_before(client: httpx.AsyncClient, cutoff: datetime) -> int:
    """Delete logs created before cutoff; returns how many were deleted."""
    out = await run_task(client, f"/{es_client.LOGS_INDEX}/_delete_by_query",
                         params={"conflicts": "proceed", "slices": "auto"},
                         json={"query": {"range": {"created_at": {"lt": cutoff.isoformat()}}}})
    return int(out.get("deleted", 0))


async def expunge(client: httpx.AsyncClient) -> None:
    await run_task(client, f"/{es_client.LOGS_INDEX}/_forcemerge", params={"only_expunge_deletes": "true"})


async def guard(client: httpx.AsyncClient, threshold: float, keep_days: int, *,
                max_days: int = MAX_DAYS_PER_RUN, now: datetime | None = None) -> dict:
    """Free disk by deleting the oldest days of logs while usage is at or above threshold."""
    now = now or datetime.now(timezone.utc)
    keep_from = now - timedelta(days=max(keep_days, 0))
    before = await disk_percent(client)
    result = {"status": "ok", "percent_before": before, "percent_after": before, "days_deleted": 0,
              "documents_deleted": 0, "deleted_before": None}
    if before is None or before < threshold:
        return result
    for _ in range(max_days):
        oldest = await oldest_log(client)
        if oldest is None:  # no logs left to delete: something else fills the disk
            result["status"] = "blocked"
            break
        day_end = datetime(oldest.year, oldest.month, oldest.day, tzinfo=timezone.utc) + timedelta(days=1)
        if day_end > keep_from:
            result["status"] = "blocked"  # only the protected newest days are left
            break
        result["documents_deleted"] += await delete_before(client, day_end)
        await expunge(client)
        result["days_deleted"] += 1
        result["deleted_before"] = day_end.isoformat()
        result["percent_after"] = await disk_percent(client)
        if result["percent_after"] is None or result["percent_after"] < threshold:
            result["status"] = "freed"
            break
    else:
        result["status"] = "still_full"  # the per-run limit was reached: the next run continues
    return result


async def _report(result: dict, threshold: float) -> None:
    from worker.agent_health import health_event
    from worker.config import REDIS_STREAM_KEY
    from worker.redis_client import get_redis
    event = "es_disk_pressure" if result["days_deleted"] else "es_disk_full"
    redis = await get_redis()
    await redis.xadd(REDIS_STREAM_KEY, health_event(
        event, agent_id=None, group_id="default", hostname="elasticsearch",
        status=result["status"], threshold=threshold, percent_before=result["percent_before"],
        percent_after=result["percent_after"], days_deleted=result["days_deleted"],
        documents_deleted=result["documents_deleted"], deleted_before=result["deleted_before"]))


async def es_disk_guard_loop() -> None:
    await asyncio.sleep(600)  # after startup and the first retention run
    while True:
        try:
            threshold = float(await get_setting("es_disk_guard_percent", "85") or 0)
            keep_days = int(await get_setting("es_disk_guard_keep_days", "3") or 3)
            if threshold > 0:
                result = await guard(es_client._get_client(), threshold, keep_days)
                if result["status"] != "ok":
                    log.warning("es_disk_guard", **result)
                    await _report(result, threshold)
        except Exception as exc:  # noqa: BLE001
            log.error("es_disk_guard_failed", error=str(exc))
        await asyncio.sleep(RUN_INTERVAL)
