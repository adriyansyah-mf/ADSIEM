# server-api/app/api/routes/knowledge.py
"""Knowledge base: analyst notes and reference material the AI uses
(worker/knowledge.py indexes, worker/knowledge_query.py retrieves)."""
import json
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import AiFeedback, KnowledgeEntry, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])
NotesPerm = require_permission("cases:manage")
SyncPerm = require_permission("settings:manage")

PAT_SOURCE = "payloadsallthethings"
SYNC_QUEUE = "siem:knowledge:sync"   # worker/knowledge.py
STATE_KEY = "siem:knowledge:pat"


class Scope(BaseModel):
    ips: list[str] = []
    hosts: list[str] = []
    users: list[str] = []
    rules: list[str] = []


class NoteIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    content: str = Field(min_length=3, max_length=20_000)
    scope: Scope = Scope()
    expires_at: datetime | None = None
    enabled: bool = True


class NoteOut(BaseModel):
    id: UUID
    group_id: str
    title: str
    content: str
    scope: dict[str, Any]
    enabled: bool
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime | None
    indexed: bool
    model_config = {"from_attributes": True}


def _out(e: KnowledgeEntry) -> NoteOut:
    return NoteOut(id=e.id, group_id=e.group_id, title=e.title, content=e.content, scope=e.scope or {},
                   enabled=e.enabled, expires_at=e.expires_at, created_at=e.created_at, updated_at=e.updated_at,
                   indexed=bool(e.indexed_at and (not e.updated_at or e.indexed_at >= e.updated_at)))


def _scope(scope: Scope) -> dict:
    from worker.knowledge_query import normalize_scope
    return normalize_scope(scope.model_dump())


def _visible(q, group_filter: str | None):
    return q if group_filter is None else q.where(KnowledgeEntry.group_id.in_((group_filter, "*")))


# ─── Notes ───────────────────────────────────────────────────────

@router.get("/notes", response_model=list[NoteOut])
async def list_notes(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    q: str = "",
):
    stmt = _visible(select(KnowledgeEntry).where(KnowledgeEntry.kind == "note"), group_filter)
    if q:
        stmt = stmt.where(or_(KnowledgeEntry.title.ilike(f"%{q}%"), KnowledgeEntry.content.ilike(f"%{q}%")))
    rows = (await db.execute(stmt.order_by(KnowledgeEntry.updated_at.desc()).limit(500))).scalars().all()
    return [_out(r) for r in rows]


@router.post("/notes", response_model=NoteOut, status_code=201)
async def create_note(
    body: NoteIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    note = KnowledgeEntry(group_id=group_filter or user.group_id or "default", kind="note", source="analyst",
                          title=body.title.strip(), content=body.content.strip(), scope=_scope(body.scope),
                          expires_at=body.expires_at, enabled=body.enabled, created_by=user.id)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    background.add_task(audit_log, db, user.id, "knowledge_note_created", "knowledge", str(note.id),
                        {"title": note.title})
    return _out(note)


async def _note(db, note_id: UUID, group_filter: str | None) -> KnowledgeEntry:
    note = await db.get(KnowledgeEntry, note_id)
    if note is None or note.kind != "note" or (group_filter is not None and note.group_id not in (group_filter, "*")):
        raise HTTPException(404, "Note not found")
    return note


@router.put("/notes/{note_id}", response_model=NoteOut)
async def update_note(
    note_id: UUID, body: NoteIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    note = await _note(db, note_id, group_filter)
    note.title, note.content, note.scope = body.title.strip(), body.content.strip(), _scope(body.scope)
    note.expires_at, note.enabled = body.expires_at, body.enabled
    await db.commit()
    await db.refresh(note)
    background.add_task(audit_log, db, user.id, "knowledge_note_updated", "knowledge", str(note.id),
                        {"title": note.title})
    return _out(note)


@router.delete("/notes/{note_id}", status_code=204)
async def delete_note(
    note_id: UUID, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    note = await _note(db, note_id, group_filter)
    title = note.title
    await db.delete(note)
    await db.commit()
    background.add_task(audit_log, db, user.id, "knowledge_note_deleted", "knowledge", str(note_id), {"title": title})


# ─── Reference sources ───────────────────────────────────────────

@router.get("/sources")
async def sources(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    total, indexed = (await db.execute(
        select(func.count(), func.count(KnowledgeEntry.indexed_at)).where(KnowledgeEntry.source == PAT_SOURCE)
    )).one()
    state: dict = {}
    try:
        raw = await (await get_redis()).hgetall(STATE_KEY)
        state = {k: (json.loads(v) if k in ("entries", "added", "updated", "removed", "unchanged") else v)
                 for k, v in raw.items()}
    except Exception:  # noqa: BLE001 — the page still shows the counts
        pass
    return {"sources": [{
        "id": PAT_SOURCE, "name": "PayloadsAllTheThings", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "license": "MIT", "entries": total, "indexed": indexed, **state,
    }]}


@router.post("/sources/payloadsallthethings/sync", status_code=202)
async def sync_now(
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(SyncPerm)],
):
    redis = await get_redis()
    await redis.rpush(SYNC_QUEUE, "1")
    await redis.hset(STATE_KEY, mapping={"status": "queued"})
    background.add_task(audit_log, db, user.id, "knowledge_sync_requested", "knowledge", PAT_SOURCE, {})
    return {"status": "queued"}


@router.get("/references")
async def references(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    q: str = "", offset: int = 0, limit: int = Query(50, le=200),
):
    stmt = select(KnowledgeEntry.id, KnowledgeEntry.title, KnowledgeEntry.source_ref, KnowledgeEntry.content).where(
        KnowledgeEntry.kind == "reference")
    if q:
        stmt = stmt.where(or_(KnowledgeEntry.title.ilike(f"%{q}%"), KnowledgeEntry.content.ilike(f"%{q}%")))
    rows = (await db.execute(stmt.order_by(KnowledgeEntry.title).offset(offset).limit(limit))).all()
    return {"items": [{"id": str(i), "title": t, "source_ref": r, "excerpt": (c or "")[:400]} for i, t, r, c in rows]}


# ─── What the AI learned from feedback ───────────────────────────

@router.get("/learned")
async def learned(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    stmt = select(AiFeedback).order_by(AiFeedback.created_at.desc()).limit(200)
    if group_filter is not None:
        stmt = stmt.where(AiFeedback.group_id == group_filter)
    rows = (await db.execute(stmt)).scalars().all()
    indexed = set((await db.execute(text(
        "SELECT feedback_id::text FROM feedback_embeddings WHERE feedback_id = ANY(CAST(:ids AS uuid[]))"
    ), {"ids": [str(r.id) for r in rows]})).scalars()) if rows else set()
    return {"items": [{
        "id": str(r.id), "entity_type": r.entity_type, "entity_id": str(r.entity_id), "context": r.context_text[:500],
        "ai_verdict": r.ai_verdict, "rating": r.rating, "correct_verdict": r.correct_verdict, "note": r.note,
        "created_at": r.created_at, "in_ai_memory": str(r.id) in indexed,
    } for r in rows]}


# ─── Preview: what the AI would get ──────────────────────────────

class PreviewIn(BaseModel):
    text: str = Field(min_length=3, max_length=5000)


@router.post("/preview")
async def preview(
    body: PreviewIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """The notes and payload reference triage would put in the prompt for this alert text."""
    from app.services.embeddings import embed
    from worker.knowledge_query import query_knowledge, text_entities

    used: list[bool] = []

    async def tracked(text_: str):
        vector = await embed(text_)
        used.append(vector is not None)
        return vector

    out = await query_knowledge(db, tracked, body.text, group_filter, text_entities(body.text), want_reference=True)
    out["semantic"] = bool(used and used[0])  # False: model unavailable, exact matches only
    return out
