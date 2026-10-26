# server-api/app/services/knowledge_vault.py
"""Knowledge vault: Markdown articles analysts write or import from an
Obsidian vault (docs/superpowers/specs/2026-10-26-hybrid-ai-investigation-
knowledge-yara-design.md, section 9).

Saving an article validates its frontmatter, blocks credentials, snapshots a
revision, rebuilds its [[wikilinks]] and asks the worker to re-index it
(worker/knowledge.py). Only published, enabled, unexpired articles reach the
AI (worker/knowledge_query.py), and every time one does is recorded here.
"""
from __future__ import annotations

import io
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from pathlib import PurePosixPath

from sqlalchemy import delete, func, or_, select, update

from app.models.models import KnowledgeEntry, KnowledgeLink, KnowledgeRevision, KnowledgeUsage
from worker import knowledge_markdown as md
from worker.knowledge_query import normalize_scope

INDEX_QUEUE = "siem:knowledge:index"  # worker/knowledge.py wakes on it

MAX_ARTICLE_CHARS = 200_000
# Obsidian import limits
MAX_ZIP_BYTES = 20 << 20
MAX_EXPANDED_BYTES = 60 << 20
MAX_FILES = 2000
MAX_FILE_BYTES = 1 << 20
MAX_RATIO = 100  # expanded / compressed: anything above is treated as a zip bomb


class VaultError(ValueError):
    """A save the vault refuses; `problems` lists why (frontmatter errors, secrets)."""

    def __init__(self, message: str, problems: list | None = None):
        super().__init__(message)
        self.problems = problems or []


@dataclass
class Saved:
    entry: KnowledgeEntry
    changed: bool
    warnings: list[str] = field(default_factory=list)


def visible(stmt, group_filter: str | None):
    return stmt if group_filter is None else stmt.where(KnowledgeEntry.group_id.in_((group_filter, "*")))


def _group_for(meta: dict, group_filter: str | None, default_group: str) -> str:
    """frontmatter scope.groups names one group (or "*"); nobody writes outside their own group."""
    groups = (meta.get("scope") or {}).get("groups") or []
    if not groups:
        return group_filter or default_group
    if len(groups) != 1:
        raise VaultError("scope.groups names one group (or \"*\" for every group)")
    wanted = groups[0]
    if group_filter is not None and wanted != group_filter:
        raise VaultError(f"you can only write to your own group ({group_filter})")
    return wanted


def _expires(meta: dict) -> datetime | None:
    if not meta.get("expires"):
        return None
    d = datetime.fromisoformat(meta["expires"])
    return d if d.tzinfo else datetime.combine(d.date(), time.max, tzinfo=timezone.utc)


async def _unique_slug(db, group_id: str, slug: str, entry_id: uuid.UUID | None) -> str:
    base, n = slug or "untitled", 1
    candidate = base
    while True:
        stmt = select(KnowledgeEntry.id).where(KnowledgeEntry.group_id == group_id, KnowledgeEntry.slug == candidate)
        if entry_id is not None:
            stmt = stmt.where(KnowledgeEntry.id != entry_id)
        clash = (await db.execute(stmt)).first()
        if clash is None:
            return candidate
        n += 1
        candidate = f"{base[:190]}-{n}"


def check(markdown: str) -> md.Article:
    """Parse and refuse what may not be stored."""
    if len(markdown) > MAX_ARTICLE_CHARS:
        raise VaultError(f"articles are limited to {MAX_ARTICLE_CHARS} characters")
    article = md.parse(markdown)
    if article.errors:
        raise VaultError("the frontmatter has errors", article.errors)
    secrets = md.find_secrets(markdown)
    if secrets:
        raise VaultError("the article contains what looks like credentials; remove them before saving",
                         [f"line {s['line']}: {s['kind']} {s['excerpt']}" for s in secrets])
    return article


async def save_article(db, *, markdown: str, user_id: uuid.UUID | None, group_filter: str | None,
                       default_group: str, entry: KnowledgeEntry | None = None, path: str | None = None,
                       status: str | None = None, may_verify: bool = False, note: str | None = None) -> Saved:
    """Create or update an article from its full Markdown. Unchanged content is a no-op."""
    article = check(markdown)
    title = md.title_of(article, path or "")
    if not title:
        raise VaultError("give the article a title (frontmatter title or a # heading)")
    meta = article.meta
    # a new article is trusted as a draft until someone reviews it (or its author says otherwise)
    trust = meta.get("trust") or (entry.trust if entry is not None else "draft")
    if trust == "verified" and not may_verify and (entry is None or entry.trust != "verified"):
        raise VaultError("only a knowledge reviewer (settings:manage) can mark an article verified")
    group_id = entry.group_id if entry is not None and not (meta.get("scope") or {}).get("groups") \
        else _group_for(meta, group_filter, default_group)
    digest = md.checksum(meta, article.body)
    if entry is not None and entry.checksum == digest and title == entry.title \
            and (status is None or status == entry.status) and (path is None or path == entry.path):
        return Saved(entry, False, article.warnings)

    created = entry is None
    if created:
        entry = KnowledgeEntry(id=uuid.uuid4(), kind="note", source="analyst" if not path else "obsidian",
                               created_by=user_id, owner_id=user_id, version=0, status=status or "draft")
        db.add(entry)
    elif status:
        entry.status = status
    scope = meta.get("scope") or {}
    entry.group_id = group_id
    entry.title, entry.content, entry.frontmatter = title, article.body.strip("\n"), meta
    entry.tags = meta.get("tags") or []
    entry.content_type = meta.get("type") or entry.content_type or "dfir_article"
    entry.trust = trust
    entry.scope = normalize_scope({k: scope.get(k) or [] for k in md.SCOPE_KEYS})
    entry.expires_at = _expires(meta)
    entry.path = path or entry.path
    entry.slug = await _unique_slug(db, group_id, md.slugify(PurePosixPath(entry.path).stem if entry.path else title),
                                    None if created else entry.id)
    entry.checksum = digest
    entry.version = (entry.version or 0) + 1
    entry.updated_at = datetime.now(timezone.utc)  # the worker re-indexes entries changed after indexed_at
    await db.flush()
    db.add(KnowledgeRevision(entry_id=entry.id, version=entry.version, title=title, content=entry.content,
                             frontmatter=meta, status=entry.status, author_id=user_id, note=note))
    await rebuild_links(db, entry, article.body)
    return Saved(entry, True, article.warnings)


async def _resolve(db, group_id: str, slug: str, title: str) -> uuid.UUID | None:
    """The article a [[link]] points at: same group or shared, by slug, title or file name."""
    row = (await db.execute(select(KnowledgeEntry.id).where(
        KnowledgeEntry.kind == "note", KnowledgeEntry.group_id.in_((group_id, "*")),
        or_(KnowledgeEntry.slug == slug, func.lower(KnowledgeEntry.title) == title.strip().lower()),
    ).limit(1))).first()
    return row[0] if row else None


async def rebuild_links(db, entry: KnowledgeEntry, body: str) -> None:
    """Replace the article's outgoing links, and resolve others' dangling links that now point at it."""
    await db.execute(delete(KnowledgeLink).where(KnowledgeLink.source_id == entry.id))
    for link in md.wikilinks(body):
        target_id = await _resolve(db, entry.group_id, link["slug"], link["target"])
        db.add(KnowledgeLink(source_id=entry.id, group_id=entry.group_id, target=link["target"][:300],
                             target_slug=link["slug"], heading=(link["heading"] or None) and link["heading"][:300],
                             target_id=target_id))
    groups = (entry.group_id,) if entry.group_id != "*" else None
    stmt = update(KnowledgeLink).where(
        KnowledgeLink.target_id.is_(None),
        or_(KnowledgeLink.target_slug == entry.slug, func.lower(KnowledgeLink.target) == entry.title.lower()))
    if groups:
        stmt = stmt.where(KnowledgeLink.group_id.in_(groups))
    await db.execute(stmt.values(target_id=entry.id))


async def links_of(db, entry: KnowledgeEntry) -> tuple[list[dict], list[dict]]:
    """(outgoing links with what they resolve to, backlinks)."""
    out_rows = (await db.execute(
        select(KnowledgeLink, KnowledgeEntry.title, KnowledgeEntry.slug)
        .outerjoin(KnowledgeEntry, KnowledgeEntry.id == KnowledgeLink.target_id)
        .where(KnowledgeLink.source_id == entry.id))).all()
    outgoing = [{"target": link.target, "heading": link.heading, "resolved": link.target_id is not None,
                 "entry_id": str(link.target_id) if link.target_id else None, "title": title, "slug": slug}
                for link, title, slug in out_rows]
    back_rows = (await db.execute(
        select(KnowledgeEntry.id, KnowledgeEntry.title, KnowledgeEntry.slug, KnowledgeLink.heading)
        .join(KnowledgeLink, KnowledgeLink.source_id == KnowledgeEntry.id)
        .where(KnowledgeLink.target_id == entry.id))).all()
    backlinks = [{"entry_id": str(i), "title": t, "slug": s, "heading": h} for i, t, s, h in back_rows]
    return outgoing, backlinks


async def related(db, entry: KnowledgeEntry, group_filter: str | None, limit: int = 5) -> list[dict]:
    """Published articles sharing a tag."""
    if not entry.tags:
        return []
    from sqlalchemy import cast, literal
    from sqlalchemy.dialects.postgresql import ARRAY, TEXT
    stmt = visible(select(KnowledgeEntry.id, KnowledgeEntry.title, KnowledgeEntry.slug).where(
        KnowledgeEntry.id != entry.id, KnowledgeEntry.kind == "note", KnowledgeEntry.status == "published",
        KnowledgeEntry.tags.op("?|")(cast(literal(list(entry.tags)), ARRAY(TEXT))),
    ), group_filter).limit(limit)
    return [{"entry_id": str(i), "title": t, "slug": s} for i, t, s in (await db.execute(stmt)).all()]


async def request_index(entry_ids: list) -> None:
    """Wake the worker's indexer; its periodic pass picks the entries up anyway if this fails."""
    try:
        from app.core.redis_client import get_redis
        redis = await get_redis()
        await redis.rpush(INDEX_QUEUE, *[str(e) for e in entry_ids])
    except Exception:  # noqa: BLE001 — recovery is the worker's periodic loop
        pass


async def record_usage(db, *, group_id: str, use_type: str, notes: list[dict], query: str | None = None,
                       investigation_id: uuid.UUID | None = None, case_id: uuid.UUID | None = None) -> None:
    """One knowledge_usage row per entry the AI retrieved or cited."""
    for n in notes:
        try:
            entry_id = uuid.UUID(str(n.get("id") or n.get("entry_id")))
        except ValueError:
            continue
        db.add(KnowledgeUsage(entry_id=entry_id, group_id=group_id, investigation_id=investigation_id,
                              case_id=case_id, use_type=use_type, query=(query or "")[:2000] or None,
                              heading=(n.get("heading") or None), version=n.get("version"),
                              score=n.get("score")))


# ─── Obsidian import ─────────────────────────────────────────────

@dataclass
class ImportReport:
    dry_run: bool
    files: int = 0
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    unresolved_links: list[dict] = field(default_factory=list)
    entry_ids: list[str] = field(default_factory=list)


def read_vault(data: bytes) -> tuple[list[tuple[str, str]], list[dict]]:
    """(path, markdown) for each note in a vault zip, and what was skipped. Refuses
    oversized archives, zip bombs and paths that escape the vault."""
    if len(data) > MAX_ZIP_BYTES:
        raise VaultError(f"the archive is larger than {MAX_ZIP_BYTES >> 20} MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise VaultError("not a zip archive")
    infos = [i for i in zf.infolist() if not i.is_dir()]
    expanded = sum(i.file_size for i in infos)
    if expanded > MAX_EXPANDED_BYTES or (data and expanded / max(len(data), 1) > MAX_RATIO and expanded > (1 << 20)):
        raise VaultError("the archive expands too much (limit "
                         f"{MAX_EXPANDED_BYTES >> 20} MB, ratio {MAX_RATIO}:1)")
    notes, skipped = [], []
    for info in infos:
        name = info.filename.replace("\\", "/")
        parts = PurePosixPath(name).parts
        if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
            raise VaultError(f"refusing a path outside the vault: {name}")
        if any(p.startswith(".") or p == "__MACOSX" for p in parts):
            continue  # .obsidian, .trash, dotfiles, macOS metadata
        if not name.lower().endswith(".md"):
            skipped.append({"path": name, "reason": "not a Markdown note"})
            continue
        if len(notes) >= MAX_FILES:
            raise VaultError(f"more than {MAX_FILES} notes")
        if info.file_size > MAX_FILE_BYTES:
            skipped.append({"path": name, "reason": f"larger than {MAX_FILE_BYTES >> 10} KB"})
            continue
        notes.append((name, zf.read(info).decode("utf-8", errors="replace")))
    # a vault zipped from its parent folder has one top directory; paths are relative to the vault
    roots = {PurePosixPath(p).parts[0] for p, _ in notes if len(PurePosixPath(p).parts) > 1}
    if len(roots) == 1 and all(len(PurePosixPath(p).parts) > 1 for p, _ in notes):
        root = roots.pop()
        notes = [(str(PurePosixPath(*PurePosixPath(p).parts[1:])), text) for p, text in notes]
        skipped = [{**s, "path": s["path"].split("/", 1)[-1] if s["path"].startswith(root + "/") else s["path"]}
                   for s in skipped]
    return notes, skipped


async def import_vault(db, data: bytes, *, user_id: uuid.UUID | None, group_filter: str | None,
                       default_group: str, publish: bool, dry_run: bool, may_verify: bool) -> ImportReport:
    """Upsert a vault's notes by path; only changed notes get a new revision and re-index.
    A dry run checks everything and writes nothing."""
    notes, skipped = read_vault(data)
    report = ImportReport(dry_run=dry_run, files=len(notes), skipped=skipped)
    group_id = group_filter or default_group
    existing = {e.path: e for e in (await db.execute(select(KnowledgeEntry).where(
        KnowledgeEntry.group_id == group_id, KnowledgeEntry.path.in_([p for p, _ in notes])))).scalars()}
    incoming_slugs: set[str] = set()
    incoming_titles: set[str] = set()
    parsed: list[tuple[str, str, md.Article]] = []
    for path, text in notes:
        try:
            article = check(text)
        except VaultError as exc:
            report.errors.append({"path": path, "error": str(exc), "problems": exc.problems})
            continue
        parsed.append((path, text, article))
        incoming_slugs.add(md.slugify(PurePosixPath(path).stem))
        incoming_titles.add(md.title_of(article, path).lower())
    for path, text, article in parsed:
        for link in md.wikilinks(article.body):
            if link["slug"] in incoming_slugs or link["target"].strip().lower() in incoming_titles:
                continue
            if await _resolve(db, group_id, link["slug"], link["target"]) is None:
                report.unresolved_links.append({"path": path, "target": link["target"]})
        entry = existing.get(path)
        if entry is not None and entry.checksum == md.checksum(article.meta, article.body) \
                and (not publish or entry.status == "published"):
            report.unchanged.append(path)
            continue
        (report.updated if entry is not None else report.added).append(path)
        if dry_run:
            continue
        try:
            saved = await save_article(db, markdown=text, user_id=user_id, group_filter=group_filter,
                                       default_group=default_group, entry=entry, path=path,
                                       status="published" if publish else (entry.status if entry else "draft"),
                                       may_verify=may_verify, note="imported from an Obsidian vault")
        except VaultError as exc:
            (report.updated if entry is not None else report.added).remove(path)
            report.errors.append({"path": path, "error": str(exc), "problems": exc.problems})
            continue
        report.entry_ids.append(str(saved.entry.id))
    if not dry_run:
        # links between notes of this import resolve now that all of them exist
        for path, _, article in parsed:
            entry = (await db.execute(select(KnowledgeEntry).where(
                KnowledgeEntry.group_id == group_id, KnowledgeEntry.path == path))).scalar_one_or_none()
            if entry is not None:
                await rebuild_links(db, entry, article.body)
    return report
