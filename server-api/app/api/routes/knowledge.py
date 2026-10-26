# server-api/app/api/routes/knowledge.py
"""Knowledge base: analyst notes and reference material the AI uses
(worker/knowledge.py indexes, worker/knowledge_query.py retrieves)."""
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import AiFeedback, KnowledgeEntry, KnowledgeRevision, User
from app.services import knowledge_vault as vault
from app.services.audit import audit_log
from worker import knowledge_markdown as md

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


def _no_secrets(*texts: str) -> None:
    found = md.find_secrets("\n".join(texts))
    if found:
        raise HTTPException(422, {"message": "the note contains what looks like credentials; remove them first",
                                  "problems": [f"line {s['line']}: {s['kind']} {s['excerpt']}" for s in found]})


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
    _no_secrets(body.title, body.content)
    note = KnowledgeEntry(group_id=group_filter or user.group_id or "default", kind="note", source="analyst",
                          title=body.title.strip(), content=body.content.strip(), scope=_scope(body.scope),
                          expires_at=body.expires_at, enabled=body.enabled, created_by=user.id, owner_id=user.id)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    await vault.request_index([note.id])
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
    _no_secrets(body.title, body.content)
    note.title, note.content, note.scope = body.title.strip(), body.content.strip(), _scope(body.scope)
    note.expires_at, note.enabled = body.expires_at, body.enabled
    await db.commit()
    await db.refresh(note)
    await vault.request_index([note.id])
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
    out["semantic"] = bool(used and used[0])  # False: model unavailable, exact and full-text matches only
    return out


# ─── Vault: Markdown articles (services/knowledge_vault.py) ──────

class ArticleIn(BaseModel):
    markdown: str = Field(min_length=1, max_length=vault.MAX_ARTICLE_CHARS)
    status: Literal["draft", "published"] | None = None


class ArticleSummary(BaseModel):
    id: UUID
    group_id: str
    kind: str
    source: str
    slug: str | None
    path: str | None
    title: str
    tags: list[str]
    content_type: str
    trust: str
    status: str
    version: int
    enabled: bool
    expires_at: datetime | None
    reviewed_at: datetime | None
    updated_at: datetime | None
    indexed: bool
    index_error: str | None
    excerpt: str


class ArticleOut(ArticleSummary):
    markdown: str
    scope: dict[str, Any]
    owner_id: UUID | None
    reviewed_by: UUID | None
    headings: list[dict[str, Any]]
    outgoing: list[dict[str, Any]] = []
    backlinks: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    warnings: list[str] = []


def _may_verify(user: User) -> bool:
    return user.role.name == "superadmin" or "settings:manage" in {p.name for p in user.role.permissions}


def _summary(e: KnowledgeEntry) -> dict:
    indexed = e.status == "published" and bool(e.indexed_at and (not e.updated_at or e.indexed_at >= e.updated_at))
    return dict(id=e.id, group_id=e.group_id, kind=e.kind, source=e.source, slug=e.slug, path=e.path, title=e.title,
                tags=e.tags or [], content_type=e.content_type, trust=e.trust, status=e.status, version=e.version,
                enabled=e.enabled, expires_at=e.expires_at, reviewed_at=e.reviewed_at, updated_at=e.updated_at,
                indexed=indexed, index_error=e.index_error, excerpt=(e.content or "")[:240])


async def _article_out(db, e: KnowledgeEntry, group_filter: str | None, warnings: list[str] | None = None) -> ArticleOut:
    outgoing, backlinks = await vault.links_of(db, e)
    return ArticleOut(**_summary(e), markdown=md.render(e.frontmatter or {}, e.content), scope=e.scope or {},
                      owner_id=e.owner_id, reviewed_by=e.reviewed_by, headings=md.headings(e.content),
                      outgoing=outgoing, backlinks=backlinks, related=await vault.related(db, e, group_filter),
                      warnings=warnings or [])


async def _article(db, article_id: UUID, group_filter: str | None) -> KnowledgeEntry:
    e = await db.get(KnowledgeEntry, article_id)
    if e is None or e.kind != "note" or (group_filter is not None and e.group_id not in (group_filter, "*")):
        raise HTTPException(404, "Article not found")
    return e


def _refused(exc: vault.VaultError) -> HTTPException:
    return HTTPException(422, {"message": str(exc), "problems": exc.problems})


@router.get("/articles", response_model=list[ArticleSummary])
async def list_articles(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    q: str = "", status: str = "", tag: str = "", content_type: str = "",
):
    """Analyst knowledge (vault articles and quick notes); synced reference material has its own list."""
    stmt = vault.visible(select(KnowledgeEntry).where(KnowledgeEntry.kind == "note"), group_filter)
    if q:
        stmt = stmt.where(or_(KnowledgeEntry.title.ilike(f"%{q}%"), KnowledgeEntry.content.ilike(f"%{q}%"),
                              KnowledgeEntry.path.ilike(f"%{q}%")))
    if status:
        stmt = stmt.where(KnowledgeEntry.status == status)
    if tag:
        stmt = stmt.where(KnowledgeEntry.tags.contains([tag]))
    if content_type:
        stmt = stmt.where(KnowledgeEntry.content_type == content_type)
    rows = (await db.execute(stmt.order_by(KnowledgeEntry.updated_at.desc()).limit(500))).scalars().all()
    return [ArticleSummary(**_summary(r)) for r in rows]


@router.get("/articles/titles")
async def article_titles(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    q: str = "",
):
    """For [[wikilink]] autocomplete."""
    stmt = vault.visible(select(KnowledgeEntry.id, KnowledgeEntry.title, KnowledgeEntry.slug)
                         .where(KnowledgeEntry.kind == "note", KnowledgeEntry.status != "archived"), group_filter)
    if q:
        stmt = stmt.where(or_(KnowledgeEntry.title.ilike(f"%{q}%"), KnowledgeEntry.slug.ilike(f"%{md.slugify(q)}%")))
    rows = (await db.execute(stmt.order_by(KnowledgeEntry.title).limit(20))).all()
    return [{"id": str(i), "title": t, "slug": s} for i, t, s in rows]


@router.get("/articles/{article_id}", response_model=ArticleOut)
async def get_article(
    article_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    return await _article_out(db, await _article(db, article_id, group_filter), group_filter)


@router.post("/articles", response_model=ArticleOut, status_code=201)
async def create_article(
    body: ArticleIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    try:
        saved = await vault.save_article(db, markdown=body.markdown, user_id=user.id, group_filter=group_filter,
                                         default_group=user.group_id or "default", status=body.status or "draft",
                                         may_verify=_may_verify(user))
    except vault.VaultError as exc:
        raise _refused(exc)
    await db.commit()
    await vault.request_index([saved.entry.id])
    background.add_task(audit_log, db, user.id, "knowledge_article_created", "knowledge", str(saved.entry.id),
                        {"title": saved.entry.title, "status": saved.entry.status})
    return await _article_out(db, saved.entry, group_filter, saved.warnings)


@router.put("/articles/{article_id}", response_model=ArticleOut)
async def update_article(
    article_id: UUID, body: ArticleIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Save a new version. A published article stays published; the worker swaps
    its chunks only once the new version embedded, so a failed index keeps the old one live."""
    entry = await _article(db, article_id, group_filter)
    try:
        saved = await vault.save_article(db, markdown=body.markdown, user_id=user.id, group_filter=group_filter,
                                         default_group=entry.group_id, entry=entry, status=body.status,
                                         may_verify=_may_verify(user))
    except vault.VaultError as exc:
        raise _refused(exc)
    await db.commit()
    if saved.changed:
        await vault.request_index([entry.id])
        background.add_task(audit_log, db, user.id, "knowledge_article_updated", "knowledge", str(entry.id),
                            {"title": entry.title, "version": entry.version})
    return await _article_out(db, entry, group_filter, saved.warnings)


async def _set_status(db, entry: KnowledgeEntry, status: str) -> None:
    entry.status = status
    entry.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await vault.request_index([entry.id])


@router.post("/articles/{article_id}/publish", response_model=ArticleOut)
async def publish_article(
    article_id: UUID, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    entry = await _article(db, article_id, group_filter)
    await _set_status(db, entry, "published")
    background.add_task(audit_log, db, user.id, "knowledge_article_published", "knowledge", str(entry.id),
                        {"title": entry.title, "version": entry.version})
    return await _article_out(db, entry, group_filter)


@router.post("/articles/{article_id}/archive", response_model=ArticleOut)
async def archive_article(
    article_id: UUID, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    entry = await _article(db, article_id, group_filter)
    await _set_status(db, entry, "archived")
    background.add_task(audit_log, db, user.id, "knowledge_article_archived", "knowledge", str(entry.id),
                        {"title": entry.title})
    return await _article_out(db, entry, group_filter)


class ReviewIn(BaseModel):
    trust: Literal["reviewed", "verified"] = "reviewed"


@router.post("/articles/{article_id}/review", response_model=ArticleOut)
async def review_article(
    article_id: UUID, body: ReviewIn, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """A second person vouches for the article; verified needs a knowledge reviewer."""
    entry = await _article(db, article_id, group_filter)
    if body.trust == "verified" and not _may_verify(user):
        raise HTTPException(403, "Marking an article verified needs the settings:manage permission")
    if entry.owner_id == user.id and user.role.name != "superadmin":
        raise HTTPException(409, "Someone other than the author reviews an article")
    entry.trust, entry.reviewed_by, entry.reviewed_at = body.trust, user.id, datetime.now(timezone.utc)
    await db.commit()
    background.add_task(audit_log, db, user.id, "knowledge_article_reviewed", "knowledge", str(entry.id),
                        {"title": entry.title, "trust": body.trust, "version": entry.version})
    return await _article_out(db, entry, group_filter)


@router.get("/articles/{article_id}/revisions")
async def article_revisions(
    article_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    entry = await _article(db, article_id, group_filter)
    rows = (await db.execute(select(KnowledgeRevision).where(KnowledgeRevision.entry_id == entry.id)
                             .order_by(KnowledgeRevision.version.desc()))).scalars().all()
    return [{"version": r.version, "title": r.title, "status": r.status, "author_id": r.author_id, "note": r.note,
             "created_at": r.created_at, "markdown": md.render(r.frontmatter or {}, r.content)} for r in rows]


@router.post("/articles/{article_id}/revisions/{version}/restore", response_model=ArticleOut)
async def restore_revision(
    article_id: UUID, version: int, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Bring back an old version as a new one; history is never rewritten."""
    entry = await _article(db, article_id, group_filter)
    rev = (await db.execute(select(KnowledgeRevision).where(
        KnowledgeRevision.entry_id == entry.id, KnowledgeRevision.version == version))).scalar_one_or_none()
    if rev is None:
        raise HTTPException(404, "Revision not found")
    try:
        saved = await vault.save_article(db, markdown=md.render(rev.frontmatter or {}, rev.content), user_id=user.id,
                                         group_filter=group_filter, default_group=entry.group_id, entry=entry,
                                         may_verify=_may_verify(user), note=f"restored version {version}")
    except vault.VaultError as exc:
        raise _refused(exc)
    await db.commit()
    await vault.request_index([entry.id])
    background.add_task(audit_log, db, user.id, "knowledge_article_restored", "knowledge", str(entry.id),
                        {"title": entry.title, "restored": version, "version": entry.version})
    return await _article_out(db, saved.entry, group_filter, saved.warnings)


@router.post("/import")
async def import_vault(
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(NotesPerm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    file: UploadFile = File(...),
    dry_run: bool = True,
    publish: bool = False,
):
    """Import an Obsidian vault (zip of Markdown notes), one way. A dry run (the
    default) reports what would change, frontmatter errors and unresolved links."""
    data = await file.read(vault.MAX_ZIP_BYTES + 1)
    try:
        report = await vault.import_vault(db, data, user_id=user.id, group_filter=group_filter,
                                          default_group=user.group_id or "default", publish=publish,
                                          dry_run=dry_run, may_verify=_may_verify(user))
    except vault.VaultError as exc:
        raise _refused(exc)
    if dry_run:
        await db.rollback()
    else:
        await db.commit()
        if report.entry_ids:
            await vault.request_index(report.entry_ids)
        background.add_task(audit_log, db, user.id, "knowledge_vault_imported", "knowledge", None,
                            {"file": file.filename, "added": len(report.added), "updated": len(report.updated),
                             "published": publish})
    return report.__dict__
