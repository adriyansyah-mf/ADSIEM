# server-api/app/services/rule_content.py
"""Rule YAML → validation (the worker's own Sigma compiler) and the row metadata derived from it."""
import hashlib
from functools import lru_cache
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from worker.sigma_engine import _compile_content
from worker.sigma_logsource import is_collected

_LEVELS = {"informational", "low", "medium", "high", "critical"}
_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# What the agents can ship without a custom decoder: the Windows agent's
# channels (agent/packaging/windows/config.yaml) on top of the decoders' log types.
AGENT_LOG_TYPES = {
    "windows_security", "windows_system", "windows_application", "windows_sysmon",
    "windows_powershell", "windows_powershell_classic", "windows_eventlog", "linux_process_exec",
}


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def compile_errors(content: str) -> list[str]:
    """Why the engine would reject this content; empty when every document compiles."""
    compiled = _compile_content(content)
    if not compiled:
        return ["rule content is empty"]
    return [f"{value[0]}: {value[1]}" for kind, value in compiled if kind == "error"]


@lru_cache(maxsize=8192)
def _parse_first(content: str) -> dict[str, Any]:
    try:
        for doc in yaml.load_all(content, Loader=_Loader):
            if isinstance(doc, dict):
                return doc
    except yaml.YAMLError:
        pass
    return {}


def first_doc(content: str) -> dict[str, Any]:
    """The rule's first YAML mapping (a copy: callers may not mutate the cached parse)."""
    return dict(_parse_first(content))


def rule_metadata(content: str) -> dict[str, Any]:
    """title/description/level/tags/mitre_tags for the rules row, from the YAML itself."""
    doc = first_doc(content)
    tags = [str(t) for t in (doc.get("tags") or []) if t is not None]
    level = str(doc.get("level") or "medium").lower()
    meta: dict[str, Any] = {
        "tags": tags,
        "mitre_tags": [t for t in tags if t.startswith("attack.")],
        "level": level if level in _LEVELS else "medium",
    }
    if doc.get("title"):
        meta["title"] = str(doc["title"])[:255]
    if doc.get("description"):
        meta["description"] = str(doc["description"])
    return meta


def logsource_of(content: str) -> dict[str, Any]:
    ls = first_doc(content).get("logsource")
    return ls if isinstance(ls, dict) else {}


async def known_log_types(db: AsyncSession) -> set[str]:
    from app.models.models import Decoder
    rows = await db.execute(select(Decoder.log_type).where(Decoder.is_enabled == True))  # noqa: E712
    return {lt for (lt,) in rows if lt} | AGENT_LOG_TYPES


def collected(content: str, log_types: set[str]) -> bool:
    doc = first_doc(content)
    if "correlation" in doc:
        return True
    return is_collected(logsource_of(content), log_types)
