# server-api/app/services/agent_policy.py
"""Per-group protection policy and exclusions for Linux and Windows agents.

A group without a policy uses the "default" group's; without that, the
built-in defaults (everything on, malware action from the global setting).
Agents get `policy_version` in heartbeats and fetch the policy when it
changes (POST /api/ingest/policy); the worker reads the alert exclusions."""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AgentPolicy

DEFAULT_GROUP = "default"
CACHE_SECONDS = 30.0
MAX_EXCLUSIONS = 500

Scope = Literal["prevention", "malware", "yara", "ransomware", "script", "alerts"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ABS = re.compile(r"^(/|[A-Za-z]:\\)")


class Exclusion(BaseModel):
    """kind: path_prefix (a file or anything under a folder), image (the
    program: full path, or a file name to match it in any folder), sha256,
    command_line (substring). scopes: what it turns off for matches."""
    kind: Literal["path_prefix", "image", "sha256", "command_line"]
    value: str = Field(min_length=1, max_length=1024)
    scopes: list[Scope] = Field(min_length=1)
    comment: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _check(self):
        v = self.value.strip()
        if self.kind == "sha256":
            v = v.lower()
            if not _SHA256.match(v):
                raise ValueError("sha256 exclusions need 64 hex characters")
        if self.kind == "path_prefix" and not _ABS.match(v):
            raise ValueError("path_prefix exclusions need an absolute path (/opt/app/ or C:\\Tools\\)")
        if self.kind == "command_line" and len(v) < 4:
            raise ValueError("command_line exclusions need at least 4 characters")
        self.value = v
        self.scopes = sorted(set(self.scopes))
        return self


class PolicySettings(BaseModel):
    prevention_enabled: bool = True          # execution prevention rules and known-malware blocking
    malware_action: Literal["off", "detect", "block"] | None = None  # None: the global setting
    yara_on_access: bool = True
    ransomware_mode: Literal["off", "report", "stop"] = "stop"
    ransomware_isolate: bool = False
    notify_user: bool = True                 # pop-ups for the signed-in user (Windows)
    # scripts scanned with the YARA rules as they run (Windows: AMSI content; Linux: interpreters'
    # code); block stops the process on a high or critical match
    script_scan: Literal["off", "detect", "block"] = "detect"
    exclusions: list[Exclusion] = Field(default_factory=list, max_length=MAX_EXCLUSIONS)

    @field_validator("exclusions")
    @classmethod
    def _unique(cls, v: list[Exclusion]) -> list[Exclusion]:
        seen, out = set(), []
        for e in v:
            key = (e.kind, e.value.lower())
            if key not in seen:
                seen.add(key)
                out.append(e)
        return out


def version_of(settings: dict) -> str:
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]


_cache: dict[str, tuple[float, dict]] = {}


def invalidate() -> None:
    _cache.clear()


async def effective(db: AsyncSession, group_id: str | None) -> dict:
    """{"group": the group whose policy applies, "settings": validated dict, "version": hash}."""
    group_id = group_id or DEFAULT_GROUP
    now = time.monotonic()
    hit = _cache.get(group_id)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    row = await db.get(AgentPolicy, group_id)
    source = group_id
    if row is None and group_id != DEFAULT_GROUP:
        row, source = await db.get(AgentPolicy, DEFAULT_GROUP), DEFAULT_GROUP
    if row is None:
        source = "built-in"
    settings = PolicySettings.model_validate(row.settings if row else {}).model_dump()
    out = {"group": source, "settings": settings, "version": version_of(settings)}
    _cache[group_id] = (now, out)
    return out
