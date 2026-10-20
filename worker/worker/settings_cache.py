# worker/worker/settings_cache.py
# Reads platform_settings from DB with a TTL cache so the worker picks up
# changes made via the UI without requiring a restart.
import asyncio
import time
import structlog
from worker.database import AsyncSessionLocal

log = structlog.get_logger()
_cache: dict = {}
_fetched_at: float = 0.0
_TTL = 60.0  # seconds

async def settings_with_prefix(prefix: str) -> dict[str, str]:
    """All settings whose key starts with prefix, keyed by the rest of the key."""
    await get_setting(prefix)  # refresh the cache when stale
    return {k[len(prefix):]: v for k, v in _cache.items() if k.startswith(prefix) and v}


async def get_setting(key: str, default: str = "") -> str:
    global _cache, _fetched_at
    if time.monotonic() - _fetched_at > _TTL:
        try:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import text
                result = await db.execute(text("SELECT key, value FROM platform_settings"))
                _cache = {row.key: row.value or "" for row in result}
                _fetched_at = time.monotonic()
        except Exception as e:
            log.warning("settings_cache_refresh_failed", error=str(e))
    return _cache.get(key, default)
