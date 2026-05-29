# SOAR Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded correlation engine with a flexible SOAR (Security Orchestration, Automation and Response) engine that lets analysts define trigger conditions and automated action playbooks from the UI.

**Architecture:** A `SoarPlaybook` row defines when to fire (trigger conditions as JSONB) and a related list of `SoarAction` rows defines what to do in order. After each alert is created in `alert_manager.py`, `soar_engine.py` evaluates all enabled playbooks against the alert context and executes matching action sequences. The existing correlation engine is kept untouched; SOAR runs as an additional layer.

**Tech Stack:** PostgreSQL JSONB for trigger/params storage, SQLAlchemy async ORM, FastAPI routes, React + TanStack Query for the frontend playbook builder UI.

---

## File Map

**Create:**
- `worker/worker/soar_engine.py` — trigger evaluator + action executor (enrich_ioc, send_webhook, create_case, suppress_alert, add_note)
- `server-api/app/api/routes/soar.py` — CRUD for playbooks and their actions
- `dashboard/src/pages/SoarPage.tsx` — Playbook list + detail editor with trigger builder and action list

**Modify:**
- `worker/worker/models.py` — add `SoarPlaybook` and `SoarAction` ORM models
- `server-api/app/models/models.py` — same two models for the API side
- `server-api/app/main.py` — add `_migrate_soar_tables()`, call in lifespan, import+register soar router
- `worker/worker/alert_manager.py` — call `run_soar_playbooks()` in `create_alert()` after the alert row is committed
- `dashboard/src/App.tsx` — import `SoarPage` and add `<Route path="/soar" ...>`
- `dashboard/src/components/Layout.tsx` — add SOAR nav item to Configuration group

---

## Trigger Condition Schema

Stored in `SoarPlaybook.trigger_conditions` as JSONB:
```json
{
  "match": "all",
  "conditions": [
    {"field": "severity",   "operator": "in",       "value": ["high", "critical"]},
    {"field": "rule_title", "operator": "contains",  "value": "SQL Injection"},
    {"field": "tags",       "operator": "contains",  "value": "attack.t1190"},
    {"field": "source_ip",  "operator": "not_null",  "value": null}
  ]
}
```

Supported fields: `severity`, `rule_title`, `source_ip`, `hostname`, `user_name`, `tags`, `mitre_tags`

Supported operators: `eq`, `neq`, `contains`, `in`, `not_null`

## Action Params Schema by Type

- `enrich_ioc` — `{}` (uses `source_ip` from alert context)
- `send_webhook` — `{"url": "https://hooks.example.com/...", "include_alert": true}`
- `create_case` — `{"title_template": "SOAR: {alert_title}", "description_template": "Auto-created from alert {alert_id}"}`
- `suppress_alert` — `{"entity_type": "ip", "duration_hours": 24, "reason": "Automated suppression"}`
- `add_note` — `{"content": "Automated SOAR action fired by playbook '{playbook_name}'."}`

---

## Task 1: Add ORM Models (Both Codebases)

**Files:**
- Modify: `worker/worker/models.py` (end of file)
- Modify: `server-api/app/models/models.py` (end of file)

- [ ] **Step 1: Add `SoarPlaybook` and `SoarAction` to `worker/worker/models.py`**

Append at the end of `worker/worker/models.py`:

```python
class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name               = Column(String(255), nullable=False)
    description        = Column(Text)
    trigger_conditions = Column(JSONB, nullable=False, default=dict)
    is_enabled         = Column(Boolean, nullable=False, default=True)
    group_id           = Column(String(100), nullable=False, default="default")
    created_at         = Column(DateTime(timezone=True), default=now_utc)
    updated_at         = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class SoarAction(Base):
    __tablename__ = "soar_actions"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False)   # enrich_ioc | send_webhook | create_case | suppress_alert | add_note
    order_index = Column(Integer, nullable=False, default=0)
    params      = Column(JSONB, nullable=False, default=dict)
    created_at  = Column(DateTime(timezone=True), default=now_utc)
```

- [ ] **Step 2: Add the same models to `server-api/app/models/models.py`**

Append at the end of `server-api/app/models/models.py`:

```python
class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name               = Column(String(255), nullable=False)
    description        = Column(Text)
    trigger_conditions = Column(JSONB, nullable=False, default=dict)
    is_enabled         = Column(Boolean, nullable=False, default=True)
    group_id           = Column(String(100), nullable=False, default="default")
    created_at         = Column(DateTime(timezone=True), default=now_utc)
    updated_at         = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class SoarAction(Base):
    __tablename__ = "soar_actions"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False)
    order_index = Column(Integer, nullable=False, default=0)
    params      = Column(JSONB, nullable=False, default=dict)
    created_at  = Column(DateTime(timezone=True), default=now_utc)
```

Check what imports `server-api/app/models/models.py` already has (UUID, JSONB, Boolean, String, Text, Integer, ForeignKey, Column, DateTime, now_utc) — they are all already imported in that file.

- [ ] **Step 3: Commit**

```bash
git add worker/worker/models.py server-api/app/models/models.py
git commit -m "feat(soar): add SoarPlaybook and SoarAction ORM models"
```

---

## Task 2: Database Migration

**Files:**
- Modify: `server-api/app/main.py`

- [ ] **Step 1: Add `_migrate_soar_tables()` function in `main.py`**

Add this function before the `lifespan` context manager (after `_migrate_alerts_columns`):

```python
async def _migrate_soar_tables() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_playbooks (
                id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name               VARCHAR(255) NOT NULL,
                description        TEXT,
                trigger_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                is_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
                group_id           VARCHAR(100) NOT NULL DEFAULT 'default',
                created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS soar_actions (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                playbook_id UUID NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
                action_type VARCHAR(50) NOT NULL,
                order_index INTEGER NOT NULL DEFAULT 0,
                params      JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_soar_actions_playbook
            ON soar_actions(playbook_id, order_index)
        """))
```

- [ ] **Step 2: Call it in the lifespan function**

Find the lifespan function in `main.py`. It currently ends with:
```python
    await _migrate_ueba_columns()
    await _migrate_alerts_columns()
    yield
```

Change to:
```python
    await _migrate_ueba_columns()
    await _migrate_alerts_columns()
    await _migrate_soar_tables()
    yield
```

- [ ] **Step 3: Verify the migration will run**

Run: `grep "_migrate_soar_tables" server-api/app/main.py`
Expected: two lines — function definition and the `await` call in lifespan.

- [ ] **Step 4: Commit**

```bash
git add server-api/app/main.py
git commit -m "feat(soar): add DB migration for soar_playbooks and soar_actions tables"
```

---

## Task 3: SOAR Engine Worker Module

**Files:**
- Create: `worker/worker/soar_engine.py`

- [ ] **Step 1: Write the failing test**

Create `worker/tests/test_soar_engine.py`:

```python
import pytest
from worker.soar_engine import _matches_trigger

def _alert(severity="high", rule_title="SQL Injection", source_ip="1.2.3.4",
           hostname="web01", user_name=None, tags=None, mitre_tags=None):
    return {
        "severity": severity,
        "rule_title": rule_title,
        "source_ip": source_ip,
        "hostname": hostname,
        "user_name": user_name,
        "tags": tags or ["attack.initial_access", "attack.t1190"],
        "mitre_tags": mitre_tags or ["attack.t1190"],
    }

def test_match_all_passes():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_match_all_fails_one():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "Brute Force"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is False

def test_match_any_passes():
    trigger = {
        "match": "any",
        "conditions": [
            {"field": "severity", "operator": "eq", "value": "low"},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_eq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "eq", "value": "high"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(severity="low")) is False

def test_neq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "neq", "value": "low"}]}
    assert _matches_trigger(trigger, _alert()) is True

def test_not_null_operator():
    trigger = {"match": "all", "conditions": [{"field": "source_ip", "operator": "not_null", "value": None}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(source_ip=None)) is False

def test_tags_contains():
    trigger = {"match": "all", "conditions": [{"field": "tags", "operator": "contains", "value": "attack.t1190"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(tags=[])) is False

def test_empty_conditions_matches():
    trigger = {"match": "all", "conditions": []}
    assert _matches_trigger(trigger, _alert()) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && python -m pytest tests/test_soar_engine.py -v 2>&1 | head -20`
Expected: `ModuleNotFoundError: No module named 'worker.soar_engine'`

- [ ] **Step 3: Create `worker/worker/soar_engine.py`**

```python
"""SOAR engine: evaluate playbook triggers and execute action sequences."""
from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import (
    Alert, AlertNote, AlertSuppression, Case, SoarAction, SoarPlaybook,
)

log = structlog.get_logger()

SUPPORTED_FIELDS = {
    "severity", "rule_title", "source_ip", "hostname",
    "user_name", "tags", "mitre_tags",
}


def _matches_condition(cond: dict, ctx: dict) -> bool:
    field = cond.get("field", "")
    operator = cond.get("operator", "eq")
    value = cond.get("value")
    actual = ctx.get(field)

    if operator == "not_null":
        return actual is not None and actual != ""
    if operator == "eq":
        return str(actual).lower() == str(value).lower()
    if operator == "neq":
        return str(actual).lower() != str(value).lower()
    if operator == "in":
        if not isinstance(value, list):
            return False
        return str(actual).lower() in [str(v).lower() for v in value]
    if operator == "contains":
        if isinstance(actual, list):
            return any(str(value).lower() in str(item).lower() for item in actual)
        return str(value).lower() in str(actual or "").lower()
    return False


def _matches_trigger(trigger: dict, ctx: dict) -> bool:
    conditions = trigger.get("conditions", [])
    if not conditions:
        return True
    match_mode = trigger.get("match", "all")
    results = [_matches_condition(c, ctx) for c in conditions]
    return all(results) if match_mode == "all" else any(results)


async def _action_enrich_ioc(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    """Run TI enrichment on the alert's source_ip and attach a note."""
    source_ip = ctx.get("source_ip")
    if not source_ip:
        return
    try:
        from worker.ti.aggregator import EnrichmentAggregator
        from worker.ti.config import TIConfig
        result = await EnrichmentAggregator(TIConfig()).enrich(source_ip)
        note_content = f"**SOAR TI Enrichment** for `{source_ip}`:\n\n{result.summary or 'No significant findings.'}"
    except Exception as exc:
        note_content = f"**SOAR TI Enrichment** failed for `{source_ip}`: {exc}"

    async with AsyncSessionLocal() as db:
        db.add(AlertNote(alert_id=alert_id, content=note_content))
        await db.commit()


async def _action_send_webhook(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    url = params.get("url", "")
    if not url:
        log.warning("soar_webhook_no_url", alert_id=str(alert_id))
        return
    payload = {
        "event": "soar_playbook_fired",
        "alert_id": str(alert_id),
        "title": ctx.get("rule_title", ""),
        "severity": ctx.get("severity", ""),
        "source_ip": ctx.get("source_ip"),
        "hostname": ctx.get("hostname"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=payload)
        log.info("soar_webhook_sent", alert_id=str(alert_id), url=url)
    except Exception as exc:
        log.warning("soar_webhook_failed", alert_id=str(alert_id), url=url, error=str(exc))


async def _action_create_case(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    title_tpl = params.get("title_template", "SOAR: {alert_title}")
    desc_tpl = params.get("description_template", "Auto-created from alert {alert_id}.")
    title = title_tpl.format(alert_title=ctx.get("rule_title", ""), alert_id=str(alert_id))
    desc = desc_tpl.format(alert_title=ctx.get("rule_title", ""), alert_id=str(alert_id))
    async with AsyncSessionLocal() as db:
        # Skip if a case already exists for this alert
        from sqlalchemy import or_
        existing = (await db.execute(
            select(Case).where(Case.alert_id == alert_id).limit(1)
        )).scalar_one_or_none()
        if existing:
            return
        db.add(Case(
            title=title,
            description=desc,
            severity=ctx.get("severity", "medium"),
            status="open",
            alert_id=alert_id,
            group_id=ctx.get("group_id", "default"),
            created_by_ai=False,
        ))
        await db.commit()
    log.info("soar_case_created", alert_id=str(alert_id))


async def _action_suppress_alert(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    entity_type = params.get("entity_type", "ip")
    reason = params.get("reason", "Automated SOAR suppression")
    group_id = ctx.get("group_id", "default")

    if entity_type == "ip":
        entity_value = ctx.get("source_ip")
    elif entity_type == "hostname":
        entity_value = ctx.get("hostname")
    elif entity_type == "rule_title":
        entity_value = ctx.get("rule_title")
    else:
        entity_value = None

    if not entity_value:
        return

    async with AsyncSessionLocal() as db:
        db.add(AlertSuppression(
            entity_type=entity_type,
            entity_value=entity_value,
            reason=reason,
            group_id=group_id,
            is_active=True,
        ))
        await db.commit()
    log.info("soar_suppression_created", entity_type=entity_type, entity_value=entity_value)


async def _action_add_note(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    content = params.get("content", "Automated SOAR action fired.")
    async with AsyncSessionLocal() as db:
        db.add(AlertNote(alert_id=alert_id, content=content))
        await db.commit()


_ACTION_HANDLERS = {
    "enrich_ioc":      _action_enrich_ioc,
    "send_webhook":    _action_send_webhook,
    "create_case":     _action_create_case,
    "suppress_alert":  _action_suppress_alert,
    "add_note":        _action_add_note,
}


async def run_soar_playbooks(
    alert_id: uuid.UUID,
    rule_match: dict,
    source_ip: str | None,
    hostname: str | None,
    user_name: str | None,
    group_id: str,
) -> None:
    ctx = {
        "severity":   rule_match.get("level", "medium"),
        "rule_title": rule_match.get("title", ""),
        "tags":       rule_match.get("tags", []),
        "mitre_tags": rule_match.get("mitre_tags", []),
        "source_ip":  source_ip,
        "hostname":   hostname,
        "user_name":  user_name,
        "group_id":   group_id,
    }

    async with AsyncSessionLocal() as db:
        q = select(SoarPlaybook).where(
            SoarPlaybook.is_enabled == True,
            (SoarPlaybook.group_id == group_id) | (SoarPlaybook.group_id == "default"),
        )
        playbooks = (await db.execute(q)).scalars().all()

        matched = []
        for pb in playbooks:
            trigger = pb.trigger_conditions or {}
            if _matches_trigger(trigger, ctx):
                actions_q = (
                    select(SoarAction)
                    .where(SoarAction.playbook_id == pb.id)
                    .order_by(SoarAction.order_index)
                )
                actions = (await db.execute(actions_q)).scalars().all()
                matched.append((pb.name, actions))

    for pb_name, actions in matched:
        log.info("soar_playbook_matched", playbook=pb_name, alert_id=str(alert_id))
        for action in actions:
            handler = _ACTION_HANDLERS.get(action.action_type)
            if not handler:
                log.warning("soar_unknown_action", action_type=action.action_type)
                continue
            try:
                await handler(alert_id, ctx, action.params or {})
            except Exception as exc:
                log.error("soar_action_failed", action_type=action.action_type,
                          playbook=pb_name, error=str(exc))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd worker && python -m pytest tests/test_soar_engine.py -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add worker/worker/soar_engine.py worker/tests/test_soar_engine.py
git commit -m "feat(soar): add SOAR engine with trigger evaluator and action library"
```

---

## Task 4: Hook SOAR Into alert_manager.py

**Files:**
- Modify: `worker/worker/alert_manager.py`

- [ ] **Step 1: Add import and call `run_soar_playbooks()` in `create_alert()`**

At the top of `worker/worker/alert_manager.py`, the imports already include `check_correlation`. Add the SOAR import alongside it:

Find this line:
```python
from worker.correlation_engine import check_correlation
```

Change to:
```python
from worker.correlation_engine import check_correlation
from worker.soar_engine import run_soar_playbooks
```

- [ ] **Step 2: Call SOAR engine after correlation check**

In `create_alert()`, after the `check_correlation` try/except block (around line 196), add:

```python
    try:
        await run_soar_playbooks(
            alert_id=alert_id,
            rule_match=rule_match,
            source_ip=source_ip,
            hostname=hostname,
            user_name=user,
            group_id=group_id,
        )
    except Exception as exc:
        log.error("soar_dispatch_failed", error=str(exc))
```

- [ ] **Step 3: Verify the placement is correct**

Run: `grep -n "soar\|correlation\|send_alert_email" worker/worker/alert_manager.py`
Expected output shows: correlation import, soar import, correlation try/except, soar try/except, email try/except — in that order.

- [ ] **Step 4: Commit**

```bash
git add worker/worker/alert_manager.py
git commit -m "feat(soar): wire run_soar_playbooks into create_alert after correlation check"
```

---

## Task 5: API Routes (server-api)

**Files:**
- Create: `server-api/app/api/routes/soar.py`
- Modify: `server-api/app/main.py`

- [ ] **Step 1: Create `server-api/app/api/routes/soar.py`**

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Any
import uuid

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import SoarAction, SoarPlaybook, User

router = APIRouter(prefix="/api/soar", tags=["soar"])


class PlaybookIn(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: dict = {}
    is_enabled: bool = True


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    is_enabled: Optional[bool] = None


class ActionIn(BaseModel):
    action_type: str
    order_index: int = 0
    params: dict = {}


class ActionUpdate(BaseModel):
    action_type: Optional[str] = None
    order_index: Optional[int] = None
    params: Optional[dict] = None


def _pb_out(pb: SoarPlaybook, actions: list[SoarAction]) -> dict:
    return {
        "id": str(pb.id),
        "name": pb.name,
        "description": pb.description,
        "trigger_conditions": pb.trigger_conditions,
        "is_enabled": pb.is_enabled,
        "group_id": pb.group_id,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
        "actions": [
            {
                "id": str(a.id),
                "action_type": a.action_type,
                "order_index": a.order_index,
                "params": a.params,
            }
            for a in sorted(actions, key=lambda x: x.order_index)
        ],
    }


@router.get("/playbooks")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    q = select(SoarPlaybook).order_by(SoarPlaybook.created_at.desc())
    if group_id:
        q = q.where(SoarPlaybook.group_id == group_id)
    playbooks = (await db.execute(q)).scalars().all()
    result = []
    for pb in playbooks:
        actions = (await db.execute(
            select(SoarAction).where(SoarAction.playbook_id == pb.id)
        )).scalars().all()
        result.append(_pb_out(pb, list(actions)))
    return result


@router.post("/playbooks", status_code=201)
async def create_playbook(
    body: PlaybookIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    pb = SoarPlaybook(
        name=body.name,
        description=body.description,
        trigger_conditions=body.trigger_conditions,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
    )
    db.add(pb)
    await db.commit()
    await db.refresh(pb)
    return _pb_out(pb, [])


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    actions = (await db.execute(
        select(SoarAction).where(SoarAction.playbook_id == pb.id)
    )).scalars().all()
    return _pb_out(pb, list(actions))


@router.patch("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    body: PlaybookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(pb, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/playbooks/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await db.delete(pb)
    await db.commit()


@router.post("/playbooks/{playbook_id}/actions", status_code=201)
async def add_action(
    playbook_id: str,
    body: ActionIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pb = await db.get(SoarPlaybook, uuid.UUID(playbook_id))
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    action = SoarAction(
        playbook_id=pb.id,
        action_type=body.action_type,
        order_index=body.order_index,
        params=body.params,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return {"id": str(action.id), "action_type": action.action_type,
            "order_index": action.order_index, "params": action.params}


@router.patch("/actions/{action_id}")
async def update_action(
    action_id: str,
    body: ActionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    action = await db.get(SoarAction, uuid.UUID(action_id))
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(action, field, value)
    await db.commit()
    return {"ok": True}


@router.delete("/actions/{action_id}", status_code=204)
async def delete_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    action = await db.get(SoarAction, uuid.UUID(action_id))
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await db.delete(action)
    await db.commit()
```

- [ ] **Step 2: Register the router in `server-api/app/main.py`**

Find this import block in `main.py`:
```python
from app.api.routes.sop import router as sop_router
```

Add after it:
```python
from app.api.routes.soar import router as soar_router
```

Find the `for router in [` block and add `soar_router,` at the end before the closing `]:`. Example — find `sop_router,` and add `soar_router,` on the next line:
```python
    hunt_schedules_router, sop_router,
    soar_router,
]:
```

- [ ] **Step 3: Verify registration**

Run: `grep "soar" server-api/app/main.py`
Expected: import line + `soar_router,` in the list.

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/soar.py server-api/app/main.py
git commit -m "feat(soar): add CRUD API routes for SOAR playbooks and actions"
```

---

## Task 6: Frontend — SoarPage

**Files:**
- Create: `dashboard/src/pages/SoarPage.tsx`
- Modify: `dashboard/src/App.tsx`
- Modify: `dashboard/src/components/Layout.tsx`

- [ ] **Step 1: Create `dashboard/src/pages/SoarPage.tsx`**

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronRight } from 'lucide-react'

const TRIGGER_FIELDS = ['severity', 'rule_title', 'source_ip', 'hostname', 'user_name', 'tags', 'mitre_tags']
const OPERATORS = ['eq', 'neq', 'contains', 'in', 'not_null']
const ACTION_TYPES = ['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note']

interface Condition {
  field: string
  operator: string
  value: string | string[] | null
}

interface TriggerConditions {
  match: 'all' | 'any'
  conditions: Condition[]
}

interface Action {
  id: string
  action_type: string
  order_index: number
  params: Record<string, string>
}

interface Playbook {
  id: string
  name: string
  description: string | null
  trigger_conditions: TriggerConditions
  is_enabled: boolean
  group_id: string
  created_at: string
  actions: Action[]
}

const emptyTrigger = (): TriggerConditions => ({ match: 'all', conditions: [] })

const S = {
  card: { background: '#161920', border: '1px solid #1e2028', borderRadius: 8, padding: 16, marginBottom: 12 } as React.CSSProperties,
  label: { fontSize: 11, color: '#64748b', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, marginBottom: 4 },
  input: {
    background: '#0d0f14', border: '1px solid #1e2028', borderRadius: 6,
    color: '#e2e8f0', fontSize: 13, padding: '6px 10px', width: '100%', outline: 'none',
  } as React.CSSProperties,
  select: {
    background: '#0d0f14', border: '1px solid #1e2028', borderRadius: 6,
    color: '#e2e8f0', fontSize: 13, padding: '6px 8px',
  } as React.CSSProperties,
  btn: (color = '#3b82f6') => ({
    padding: '6px 14px', borderRadius: 6, border: 'none',
    background: color, color: '#fff', fontSize: 12, fontWeight: 600,
    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
  } as React.CSSProperties),
  ghost: { padding: '4px 8px', borderRadius: 4, border: 'none', background: 'transparent', cursor: 'pointer', color: '#64748b' } as React.CSSProperties,
}

function ConditionRow({
  cond, onChange, onRemove,
}: { cond: Condition; onChange: (c: Condition) => void; onRemove: () => void }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
      <select style={S.select} value={cond.field} onChange={e => onChange({ ...cond, field: e.target.value })}>
        {TRIGGER_FIELDS.map(f => <option key={f}>{f}</option>)}
      </select>
      <select style={S.select} value={cond.operator} onChange={e => onChange({ ...cond, operator: e.target.value })}>
        {OPERATORS.map(o => <option key={o}>{o}</option>)}
      </select>
      {cond.operator !== 'not_null' && (
        <input
          style={{ ...S.input, flex: 1 }}
          value={Array.isArray(cond.value) ? cond.value.join(',') : (cond.value ?? '')}
          placeholder={cond.operator === 'in' ? 'val1,val2' : 'value'}
          onChange={e => {
            const raw = e.target.value
            onChange({ ...cond, value: cond.operator === 'in' ? raw.split(',').map(s => s.trim()) : raw })
          }}
        />
      )}
      <button style={S.ghost} onClick={onRemove}><Trash2 size={13} /></button>
    </div>
  )
}

function ActionRow({
  action, onUpdate, onRemove,
}: { action: Action; onUpdate: (params: Record<string, string>) => void; onRemove: () => void }) {
  const [open, setOpen] = useState(false)
  const paramKeys: Record<string, string[]> = {
    send_webhook: ['url'],
    create_case: ['title_template', 'description_template'],
    suppress_alert: ['entity_type', 'duration_hours', 'reason'],
    add_note: ['content'],
  }
  const keys = paramKeys[action.action_type] || []

  return (
    <div style={{ ...S.card, padding: 12, marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11, color: '#94a3b8', background: '#1e2028', padding: '2px 8px', borderRadius: 4 }}>
            #{action.order_index + 1}
          </span>
          <span style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 500 }}>{action.action_type}</span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {keys.length > 0 && (
            <button style={S.ghost} onClick={() => setOpen(o => !o)}>
              {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            </button>
          )}
          <button style={S.ghost} onClick={onRemove}><Trash2 size={13} /></button>
        </div>
      </div>

      {open && keys.length > 0 && (
        <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
          {keys.map(k => (
            <div key={k}>
              <div style={S.label}>{k}</div>
              <input
                style={S.input}
                value={action.params[k] ?? ''}
                onChange={e => onUpdate({ ...action.params, [k]: e.target.value })}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PlaybookEditor({ playbook, onClose }: { playbook: Playbook | null; onClose: () => void }) {
  const qc = useQueryClient()
  const isNew = playbook === null

  const [name, setName] = useState(playbook?.name ?? '')
  const [description, setDescription] = useState(playbook?.description ?? '')
  const [trigger, setTrigger] = useState<TriggerConditions>(playbook?.trigger_conditions ?? emptyTrigger())
  const [actions, setActions] = useState<Action[]>(playbook?.actions ?? [])

  const savePlaybook = useMutation({
    mutationFn: async () => {
      if (isNew) {
        const resp = await api.post('/api/soar/playbooks', { name, description, trigger_conditions: trigger })
        const pb = resp.data
        for (const act of actions) {
          await api.post(`/api/soar/playbooks/${pb.id}/actions`, {
            action_type: act.action_type, order_index: act.order_index, params: act.params,
          })
        }
      } else {
        await api.patch(`/api/soar/playbooks/${playbook!.id}`, { name, description, trigger_conditions: trigger })
        for (const act of actions) {
          if (act.id.startsWith('new-')) {
            await api.post(`/api/soar/playbooks/${playbook!.id}/actions`, {
              action_type: act.action_type, order_index: act.order_index, params: act.params,
            })
          } else {
            await api.patch(`/api/soar/actions/${act.id}`, { params: act.params, order_index: act.order_index })
          }
        }
      }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['soar-playbooks'] }); onClose() },
  })

  const addCondition = () =>
    setTrigger(t => ({ ...t, conditions: [...t.conditions, { field: 'severity', operator: 'eq', value: 'high' }] }))

  const addAction = (type: string) =>
    setActions(a => [...a, { id: `new-${Date.now()}`, action_type: type, order_index: a.length, params: {} }])

  const removeAction = async (act: Action) => {
    if (!act.id.startsWith('new-') && playbook) {
      await api.delete(`/api/soar/actions/${act.id}`)
      qc.invalidateQueries({ queryKey: ['soar-playbooks'] })
    }
    setActions(a => a.filter(x => x.id !== act.id))
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#111318', border: '1px solid #1e2028', borderRadius: 10, padding: 24, width: 680, maxHeight: '90vh', overflow: 'auto' }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0', marginBottom: 20 }}>
          {isNew ? 'New Playbook' : 'Edit Playbook'}
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={S.label}>Name</div>
          <input style={S.input} value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div style={{ marginBottom: 20 }}>
          <div style={S.label}>Description</div>
          <input style={S.input} value={description} onChange={e => setDescription(e.target.value)} />
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Trigger Conditions</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: '#64748b' }}>Match</span>
              <select style={S.select} value={trigger.match} onChange={e => setTrigger(t => ({ ...t, match: e.target.value as 'all' | 'any' }))}>
                <option value="all">ALL</option>
                <option value="any">ANY</option>
              </select>
              <button style={S.btn('#1e2028')} onClick={addCondition}><Plus size={13} /> Add</button>
            </div>
          </div>
          {trigger.conditions.length === 0 && (
            <div style={{ fontSize: 12, color: '#3f4558', fontStyle: 'italic' }}>No conditions — playbook fires on every alert</div>
          )}
          {trigger.conditions.map((c, i) => (
            <ConditionRow
              key={i}
              cond={c}
              onChange={nc => setTrigger(t => ({ ...t, conditions: t.conditions.map((x, j) => j === i ? nc : x) }))}
              onRemove={() => setTrigger(t => ({ ...t, conditions: t.conditions.filter((_, j) => j !== i) }))}
            />
          ))}
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Actions</div>
            <select
              style={S.select}
              onChange={e => { if (e.target.value) { addAction(e.target.value); e.target.value = '' } }}
              defaultValue=""
            >
              <option value="" disabled>+ Add action</option>
              {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          {actions.length === 0 && (
            <div style={{ fontSize: 12, color: '#3f4558', fontStyle: 'italic' }}>No actions defined</div>
          )}
          {actions.map((act, i) => (
            <ActionRow
              key={act.id}
              action={{ ...act, order_index: i }}
              onUpdate={params => setActions(a => a.map(x => x.id === act.id ? { ...x, params } : x))}
              onRemove={() => removeAction(act)}
            />
          ))}
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button style={{ ...S.btn('#1e2028'), color: '#94a3b8' }} onClick={onClose}>Cancel</button>
          <button style={S.btn()} onClick={() => savePlaybook.mutate()} disabled={!name.trim()}>
            {savePlaybook.isPending ? 'Saving...' : 'Save Playbook'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function SoarPage() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<Playbook | null | undefined>(undefined)

  const { data: playbooks = [], isLoading } = useQuery<Playbook[]>({
    queryKey: ['soar-playbooks'],
    queryFn: () => api.get('/api/soar/playbooks').then(r => r.data),
  })

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/api/soar/playbooks/${id}`, { is_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/soar/playbooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  return (
    <div>
      {editing !== undefined && (
        <PlaybookEditor playbook={editing} onClose={() => setEditing(undefined)} />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>SOAR Playbooks</div>
          <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
            Define trigger conditions and automated response actions
          </div>
        </div>
        <button style={S.btn()} onClick={() => setEditing(null)}>
          <Plus size={14} /> New Playbook
        </button>
      </div>

      {isLoading && <div style={{ color: '#64748b', fontSize: 13 }}>Loading...</div>}

      {!isLoading && playbooks.length === 0 && (
        <div style={{ ...S.card, textAlign: 'center', padding: 48 }}>
          <Shield size={32} color="#3f4558" style={{ margin: '0 auto 12px' }} />
          <div style={{ color: '#64748b', fontSize: 14 }}>No playbooks defined yet.</div>
          <div style={{ color: '#3f4558', fontSize: 12, marginTop: 4 }}>
            Create a playbook to automate responses to alerts.
          </div>
        </div>
      )}

      {playbooks.map(pb => (
        <div key={pb.id} style={S.card}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 14, fontWeight: 600, color: pb.is_enabled ? '#e2e8f0' : '#475569' }}>
                  {pb.name}
                </span>
                <span style={{
                  fontSize: 11, padding: '1px 8px', borderRadius: 3,
                  background: pb.is_enabled ? 'rgba(52,211,153,0.1)' : '#1e2028',
                  color: pb.is_enabled ? '#34d399' : '#475569',
                }}>
                  {pb.is_enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
              {pb.description && (
                <div style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>{pb.description}</div>
              )}
              <div style={{ display: 'flex', gap: 12, fontSize: 12, color: '#475569' }}>
                <span>{pb.trigger_conditions?.conditions?.length ?? 0} condition(s)</span>
                <span>·</span>
                <span>{pb.actions.length} action(s)</span>
                <span>·</span>
                <span>Match: {pb.trigger_conditions?.match?.toUpperCase() ?? 'ALL'}</span>
              </div>
              {pb.actions.length > 0 && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {pb.actions.map(a => (
                    <span key={a.id} style={{
                      fontSize: 11, background: '#1a1f2e', border: '1px solid #2d3748',
                      borderRadius: 4, padding: '2px 8px', color: '#7dd3fc',
                    }}>
                      {a.action_type}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6, marginLeft: 16 }}>
              <button
                style={S.ghost}
                title={pb.is_enabled ? 'Disable' : 'Enable'}
                onClick={() => toggle.mutate({ id: pb.id, enabled: !pb.is_enabled })}
              >
                {pb.is_enabled
                  ? <ToggleRight size={18} color="#34d399" />
                  : <ToggleLeft size={18} color="#475569" />}
              </button>
              <button style={S.ghost} onClick={() => setEditing(pb)}>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>Edit</span>
              </button>
              <button style={S.ghost} onClick={() => { if (confirm(`Delete "${pb.name}"?`)) del.mutate(pb.id) }}>
                <Trash2 size={14} color="#ef4444" />
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Register the route in `dashboard/src/App.tsx`**

Add the import after the SopPage import:
```tsx
import SoarPage from '@/pages/SoarPage'
```

Add the route inside the `<Route element={<Layout />}>` block after the correlation route:
```tsx
<Route path="/soar" element={<SoarPage />} />
```

- [ ] **Step 3: Add SOAR to the sidebar in `dashboard/src/components/Layout.tsx`**

In `Layout.tsx`, find the Configuration group in `NAV_GROUPS`:
```typescript
  {
    label: 'Configuration',
    items: [
      { to: '/agents', label: 'Agents', icon: Server },
      { to: '/rules', label: 'Rules', icon: BookOpen },
      { to: '/decoders', label: 'Decoders', icon: Wrench },
      { to: '/correlation', label: 'Correlation', icon: GitMerge },
    ],
  },
```

Add `Shield` to the lucide-react import at the top of `Layout.tsx` (it's already imported if you scan — if not, add it to the destructured import list).

Then add the SOAR item to the Configuration group:
```typescript
      { to: '/soar', label: 'SOAR', icon: Shield },
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/pages/SoarPage.tsx dashboard/src/App.tsx dashboard/src/components/Layout.tsx
git commit -m "feat(soar): add SOAR playbook UI page with trigger builder and action editor"
```

---

## Self-Review

### Spec Coverage

| Requirement | Task |
|---|---|
| Trigger on alert attributes (severity, rule_title, source_ip, hostname, user_name, tags/MITRE) | Task 3 `_matches_condition` |
| Playbooks with ordered action steps | Task 1 `SoarAction.order_index`, Task 5 API |
| Action: enrich IOC (TI engine) | Task 3 `_action_enrich_ioc` |
| Action: send webhook | Task 3 `_action_send_webhook` |
| Action: create case automatically | Task 3 `_action_create_case` |
| Action: suppress future alerts | Task 3 `_action_suppress_alert` |
| Action: add alert note | Task 3 `_action_add_note` |
| Build on top of existing features | Task 4: SOAR added alongside correlation, not replacing it |
| Frontend UI | Task 6 `SoarPage.tsx` |

### Placeholder Scan
- No TBD or TODO in code steps
- All function signatures match their callers
- `enrich_ioc` calls `enrich(TIConfig(), source_ip)` — verify `aggregator.enrich` exists and has this signature before Task 3 execution (it may need adaptation)

### Type Consistency
- `run_soar_playbooks(alert_id, rule_match, source_ip, hostname, user_name, group_id)` — called in Task 4 with matching parameters
- `SoarPlaybook` and `SoarAction` model names are consistent across Task 1, 2, 3, 5
- `_pb_out()` in API routes references `pb.trigger_conditions`, `pb.created_at` — all in model

### Note on TI Aggregator
The TI aggregator is `EnrichmentAggregator(TIConfig()).enrich(text)` — this has been verified from the source (`worker/worker/ti/aggregator.py:120`). The `enrich()` method takes a raw text/IP string and extracts IOCs from it automatically.
