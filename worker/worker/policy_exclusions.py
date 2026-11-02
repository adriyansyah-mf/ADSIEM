# worker/worker/policy_exclusions.py
"""Group policy exclusions with the "alerts" scope (server-api
services/agent_policy.py): an event a rule matched raises no alert when it
is about an excluded program, file, hash or command line."""
from __future__ import annotations

import re
import time

import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal

log = structlog.get_logger()
CACHE_SECONDS = 60.0
DEFAULT_GROUP = "default"

IMAGE_FIELDS = ("Image", "process.executable", "SourceImage", "process.name")
PATH_FIELDS = ("TargetFilename", "file.path", "ImageLoaded", "dll.path", "Image", "process.executable",
               "SourceFilename")
HASH_FIELDS = ("file.hash.sha256", "process.hash.sha256", "sha256", "SHA256")
CMD_FIELDS = ("CommandLine", "process.command_line")
_SHA_IN_HASHES = re.compile(r"SHA256=([0-9A-Fa-f]{64})")

_cache: tuple[float, dict[str, list[dict]]] | None = None


async def _load() -> dict[str, list[dict]]:
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    out: dict[str, list[dict]] = {}
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("SELECT group_id, settings FROM agent_policies"))).all()
        for group_id, settings in rows:
            out[group_id] = [e for e in (settings or {}).get("exclusions") or []
                             if "alerts" in (e.get("scopes") or [])]
    except Exception as exc:  # noqa: BLE001 — no table yet (older server): nothing is excluded
        log.debug("policy_exclusions_unavailable", error=str(exc))
    _cache = (now, out)
    return out


def _base(p: str) -> str:
    return re.split(r"[\\/]", p)[-1]


def matches(exclusion: dict, event: dict) -> bool:
    kind, value = exclusion.get("kind"), str(exclusion.get("value") or "")
    if not value:
        return False
    v = value.lower()
    if kind == "image":
        full = "/" in value or "\\" in value
        for f in IMAGE_FIELDS:
            got = str(event.get(f) or "").lower()
            if got and (got == v if full else _base(got) == v):
                return True
    elif kind == "path_prefix":
        return any(str(event.get(f) or "").lower().startswith(v) for f in PATH_FIELDS)
    elif kind == "sha256":
        if any(str(event.get(f) or "").lower() == v for f in HASH_FIELDS):
            return True
        m = _SHA_IN_HASHES.search(str(event.get("Hashes") or event.get("process.hash") or ""))
        return bool(m and m.group(1).lower() == v)
    elif kind == "command_line":
        return any(v in str(event.get(f) or "").lower() for f in CMD_FIELDS)
    return False


async def excluded(event: dict, group_id: str | None) -> dict | None:
    """The first alert exclusion of the group's policy (or the default
    group's, when the group has none) that matches the event."""
    policies = await _load()
    group_id = group_id or DEFAULT_GROUP
    rules = policies.get(group_id)
    if rules is None:
        rules = policies.get(DEFAULT_GROUP, [])
    for e in rules:
        if matches(e, event):
            return e
    return None
