# worker/worker/ti/cache.py
"""Redis-backed caching for threat-intel provider lookups, keyed per
tenant/provider/indicator with a provider-specific TTL. On a live fetch
failure, serves a stale cached value (marked) rather than failing outright --
enrichment should degrade gracefully, not break, when a provider is down."""
from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

CACHE_KEY_PREFIX = "ti:cache"

# How long a provider's result is considered fresh. More volatile signals
# (GreyNoise "currently scanning" activity) get shorter TTLs than
# slow-changing ones (WHOIS registration, GeoIP).
DEFAULT_TTL_SECONDS = 3600
PROVIDER_TTL_SECONDS: dict[str, int] = {
    "virustotal": 6 * 3600,
    "abuseipdb": 3600,
    "otx": 3600,
    "greynoise": 900,
    "shodan": 6 * 3600,
    "urlhaus": 1800,
    "whois": 24 * 3600,
    "geoip": 24 * 3600,
}

# A stale entry is kept around this many times longer than its fresh TTL, so
# it remains available as a fallback well after it stops being "fresh".
STALE_RETENTION_MULTIPLIER = 4


def cache_key(tenant: str, provider: str, lookup_type: str, indicator: str) -> str:
    return f"{CACHE_KEY_PREFIX}:{tenant}:{provider}:{lookup_type}:{indicator}"


async def get_or_fetch(
    redis: Any,
    *,
    tenant: str,
    provider: str,
    lookup_type: str,
    indicator: str,
    fetch: Callable[[], Awaitable[dict[str, Any]]],
    ttl_seconds: int | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Return a provider result dict augmented with `_stale` and `_cached`
    markers. Behavior:
    - fresh cache hit -> cached result, `_stale=False`, `_cached=True`
    - cache miss/expired, fetch succeeds -> live result, `_stale=False`, `_cached=False`, cached for next time
    - cache miss/expired, fetch fails, a stale copy exists -> stale result, `_stale=True`, `_cached=True`, `_error` set
    - cache miss, fetch fails, no stale copy -> the fetch exception propagates
    """
    key = cache_key(tenant, provider, lookup_type, indicator)
    ttl = ttl_seconds if ttl_seconds is not None else PROVIDER_TTL_SECONDS.get(provider, DEFAULT_TTL_SECONDS)
    current_time = now if now is not None else time.time()

    cached_raw = await redis.get(key)
    if cached_raw is not None:
        entry = json.loads(cached_raw)
        if entry.get("_cached_until", 0) > current_time:
            result = dict(entry["result"])
            result["_stale"] = False
            result["_cached"] = True
            return result

    try:
        result = await fetch()
    except Exception as exc:
        if cached_raw is not None:
            entry = json.loads(cached_raw)
            stale_result = dict(entry["result"])
            stale_result["_stale"] = True
            stale_result["_cached"] = True
            stale_result["_error"] = str(exc)
            return stale_result
        raise

    entry = {"result": result, "_cached_until": current_time + ttl}
    await redis.set(key, json.dumps(entry), ex=ttl * STALE_RETENTION_MULTIPLIER)
    output = dict(result)
    output["_stale"] = False
    output["_cached"] = False
    return output
