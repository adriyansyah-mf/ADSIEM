"""The enabled YARA rule set that agents use for on-access scanning.

Heartbeats carry only its hash; agents fetch the rules from
POST /api/ingest/yara-rules when the hash changes. The set is cached for
a short time so heartbeats do not read every rule's content."""
import hashlib
import json
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import YaraRule

CACHE_SECONDS = 30.0

_cache: tuple[float, str, list[dict]] | None = None


def invalidate() -> None:
    """Call after a rule changes (this process sees it at once; other
    replicas within CACHE_SECONDS)."""
    global _cache
    _cache = None


def ruleset_hash(rules: list[dict]) -> str:
    if not rules:
        return ""
    canonical = json.dumps(sorted((r["id"], r["name"], r["content"]) for r in rules))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def enabled_ruleset(db: AsyncSession) -> tuple[str, list[dict]]:
    """(hash, rules) of the enabled rules; hash is "" when there are none."""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_SECONDS:
        return _cache[1], _cache[2]
    result = await db.execute(select(YaraRule).where(YaraRule.is_enabled == True).order_by(YaraRule.name))  # noqa: E712
    rules = [{"id": str(r.id), "name": r.name, "content": r.content} for r in result.scalars().all()]
    digest = ruleset_hash(rules)
    _cache = (now, digest, rules)
    return digest, rules
