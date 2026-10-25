# server-api/app/api/routes/prevention_rules.py
"""Execution prevention rules (roadmap 3.3).

Operators manage the rules here; Linux agents poll POST
/api/ingest/prevention-rules (agent/internal/prevent) and enforce them
with the BPF LSM or fanotify. A rule only stops a program when its action
is "block"; new rules default to "detect"."""
import hashlib
import json
import re
import time
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_current_user, require_permission
from app.models.models import Agent, ExecPreventionRule

router = APIRouter(prefix="/api/prevention-rules", tags=["prevention"])
agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_NAME = re.compile(r"^[^/\s,]{1,31}$")


def _names(s: str) -> list[str]:
    return [n.strip() for n in s.split(",") if n.strip()]


class PreventionRuleIn(BaseModel):
    name: str
    description: str | None = None
    rule_type: Literal["hash", "path", "dir", "parent"]
    value: str
    parent: str = ""
    action: Literal["detect", "block"] = "detect"

    @model_validator(mode="after")
    def _check(self):
        v = self.value.strip()
        if self.rule_type == "hash" and not _SHA256.match(v):
            raise ValueError("hash rules need a SHA-256 (64 hex characters)")
        if self.rule_type in ("path", "dir") and not v.startswith("/"):
            raise ValueError(f"{self.rule_type} rules need an absolute path")
        if self.rule_type == "parent":
            parents, children = _names(self.parent), _names(v)
            if not parents or not children:
                raise ValueError("parent rules need parent names and child names")
            bad = [n for n in parents + children if not _NAME.match(n)]
            if bad:
                raise ValueError(f"names are executable basenames up to 31 characters: {bad}")
        self.value = v.lower() if self.rule_type == "hash" else v
        return self


class PreventionRuleOut(BaseModel):
    id: UUID
    name: str
    description: str | None
    rule_type: str
    value: str
    parent: str
    action: str
    is_enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── rule set for agents (hash + short cache) ─────────────────────────

CACHE_SECONDS = 30.0
_cache: tuple[float, str, list[dict]] | None = None


def invalidate() -> None:
    global _cache
    _cache = None


def ruleset_hash(rules: list[dict]) -> str:
    if not rules:
        return ""
    return hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()


async def enabled_ruleset(db: AsyncSession) -> tuple[str, list[dict]]:
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_SECONDS:
        return _cache[1], _cache[2]
    result = await db.execute(
        select(ExecPreventionRule).where(ExecPreventionRule.is_enabled == True)  # noqa: E712
        .order_by(ExecPreventionRule.name))
    rules = [{"id": str(r.id), "name": r.name, "rule_type": r.rule_type, "value": r.value,
              "parent": r.parent or "", "action": r.action} for r in result.scalars().all()]
    digest = ruleset_hash(rules)
    _cache = (now, digest, rules)
    return digest, rules


class RulesRequest(BaseModel):
    loaded_hash: str = ""


@agent_router.post("/prevention-rules")
async def agent_prevention_rules(
    body: RulesRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    digest, rules = await enabled_ruleset(db)
    if body.loaded_hash and body.loaded_hash == digest:
        return {"hash": digest, "unchanged": True, "rules": []}
    return {"hash": digest, "unchanged": False, "rules": rules}


# ─── operator API ──────────────────────────────────────────────────────

async def _get(db: AsyncSession, rule_id: UUID) -> ExecPreventionRule:
    r = await db.get(ExecPreventionRule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    return r


@router.get("", response_model=list[PreventionRuleOut])
async def list_rules(db: Annotated[AsyncSession, Depends(get_db)], _=Depends(get_current_user)):
    result = await db.execute(select(ExecPreventionRule).order_by(ExecPreventionRule.name))
    return result.scalars().all()


@router.post("", response_model=PreventionRuleOut, status_code=201)
async def create_rule(body: PreventionRuleIn, db: Annotated[AsyncSession, Depends(get_db)],
                      _=Depends(require_permission("rules:create"))):
    if (await db.execute(select(ExecPreventionRule).where(ExecPreventionRule.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "A rule with this name exists")
    r = ExecPreventionRule(**body.model_dump())
    db.add(r)
    await db.commit()
    await db.refresh(r)
    invalidate()
    return r


@router.put("/{rule_id}", response_model=PreventionRuleOut)
async def update_rule(rule_id: UUID, body: PreventionRuleIn, db: Annotated[AsyncSession, Depends(get_db)],
                      _=Depends(require_permission("rules:update"))):
    r = await _get(db, rule_id)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await db.commit()
    await db.refresh(r)
    invalidate()
    return r


@router.patch("/{rule_id}/toggle", response_model=PreventionRuleOut)
async def toggle_rule(rule_id: UUID, db: Annotated[AsyncSession, Depends(get_db)],
                      _=Depends(require_permission("rules:update"))):
    r = await _get(db, rule_id)
    r.is_enabled = not r.is_enabled
    await db.commit()
    await db.refresh(r)
    invalidate()
    return r


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: UUID, db: Annotated[AsyncSession, Depends(get_db)],
                      _=Depends(require_permission("rules:delete"))):
    r = await _get(db, rule_id)
    await db.delete(r)
    await db.commit()
    invalidate()
