"""On-demand threat-intel lookups for the investigation chat.

server-api cannot import this package's TI code, so it pushes a job
{id, value, group, requested_at} on the Redis list `siem:ti:lookup`; this loop
runs EnrichmentAggregator on the single IoC and writes the summary (or
{"error": ...}) to `siem:ti:result:<id>` with a 10 minute TTL. The loop never
dies on a bad job, a provider failure or a Redis hiccup.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re

import structlog

log = structlog.get_logger()

QUEUE = "siem:ti:lookup"
RESULT_PREFIX = "siem:ti:result:"
RESULT_TTL = 600
CONCURRENCY = 4
MAX_VALUE = 512

_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
_URL = re.compile(r"^https?://[^\s/?#]+(?:[/?#]\S*)?$", re.I)


def check_value(value) -> str:
    """The value as a single IoC (public ip, domain, http(s) url, md5/sha1/sha256), or ValueError."""
    if not isinstance(value, str):
        raise ValueError("value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("value is empty")
    if len(v) > MAX_VALUE:
        raise ValueError(f"value is longer than {MAX_VALUE} characters")
    if re.search(r"\s", v):
        raise ValueError("give one IoC (ip, domain, url or hash), not free text")
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise ValueError("private or reserved addresses are not looked up")
        return str(ip)
    if _HASH.match(v):
        return v.lower()
    if _URL.match(v):
        return v
    if _DOMAIN.match(v):
        return v.lower()
    raise ValueError("not an ip, domain, url or md5/sha1/sha256 hash")


async def _aggregator():
    from worker.ai_analyst import _build_ti_config
    from worker.ti.aggregator import EnrichmentAggregator

    return EnrichmentAggregator(await _build_ti_config())


async def handle(redis, raw, aggregator) -> None:
    """Serve one queued job. Never raises."""
    try:
        data = json.loads(raw)
        job_id = str(data["id"])
        if not job_id or len(job_id) > 100:
            raise ValueError("bad id")
    except Exception:  # noqa: BLE001 — nobody to answer
        log.warning("ti_lookup_bad_job")
        return
    key = RESULT_PREFIX + job_id
    try:
        try:
            value = check_value(data.get("value"))
            result = (await aggregator.enrich(value)).model_dump(mode="json")
        except ValueError as exc:
            result = {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001 — the waiting chat turn gets the reason
            log.warning("ti_lookup_failed", job=job_id, error=str(exc))
            result = {"error": f"lookup failed: {str(exc)[:300] or type(exc).__name__}"}
        await redis.set(key, json.dumps(result, default=str), ex=RESULT_TTL)
    except Exception as exc:  # noqa: BLE001
        log.warning("ti_lookup_result_not_written", job=job_id, error=str(exc))


async def ti_lookup_loop(redis=None, aggregator_factory=_aggregator, retry_delay: float = 2.0) -> None:
    if redis is None:
        from worker.redis_client import get_redis
        redis = await get_redis()
    slots = asyncio.Semaphore(CONCURRENCY)
    running: set[asyncio.Task] = set()

    async def serve(raw) -> None:
        try:
            try:
                aggregator = await aggregator_factory()
            except Exception as exc:  # noqa: BLE001
                log.warning("ti_lookup_config_failed", error=str(exc))

                class _Down:
                    async def enrich(self, _text):
                        raise RuntimeError("threat-intel providers are not configured")
                aggregator = _Down()
            await handle(redis, raw, aggregator)
        finally:
            slots.release()

    try:
        while True:
            await slots.acquire()
            try:
                item = await redis.blpop(QUEUE, timeout=5)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                slots.release()
                log.warning("ti_lookup_pop_failed", error=str(exc))
                await asyncio.sleep(retry_delay)
                continue
            if not item:
                slots.release()
                continue
            task = asyncio.create_task(serve(item[1]))
            running.add(task)
            task.add_done_callback(running.discard)
    finally:
        for task in running:
            task.cancel()
