# worker/worker/knowledge.py
"""Knowledge base upkeep: embed analyst notes and reference material, and sync
PayloadsAllTheThings (swisskyrepo/PayloadsAllTheThings, MIT) as reference.

Entries live in knowledge_entries; this loop chunks and embeds any entry that
is new or changed (indexed_at NULL or older than updated_at) into
knowledge_chunks. Retrieval is worker/knowledge_query.py.

PayloadsAllTheThings is fetched as a zip (Settings → knowledge_pat_url, a
GitHub codeload URL by default, so an internal mirror works too), split into
one entry per markdown section with its payloads, and refreshed weekly or on
demand from the Knowledge page. Only changed sections are re-embedded.
"""
from __future__ import annotations

import asyncio
import io
import json
import re
import zipfile
from datetime import datetime, timezone

import structlog
from sqlalchemy import text

from worker import knowledge_markdown as md
from worker.database import AsyncSessionLocal
from worker.knowledge_query import alert_entities, alert_query_text, query_knowledge, wants_payload_reference
from worker.rag import embed_or_none, embed_texts
from worker.settings_cache import get_setting

log = structlog.get_logger()

LOOP_INTERVAL = 60
INDEX_BATCH = 25        # entries per commit: progress survives a restart
EMBED_BATCH = 4         # chunks per model call; 64 peaks ~1.7 GB, the worker has 512 MB
INDEX_LOCK_TTL = 300    # refreshed every batch, so a killed worker frees it quickly
CHUNK_CHARS = 1200
SYNC_EVERY_DAYS = 7
MAX_ZIP_BYTES = 150 << 20
MAX_SECTION_CHARS = 6000
PAT_SOURCE = "payloadsallthethings"
DEFAULT_PAT_URL = "https://codeload.github.com/swisskyrepo/PayloadsAllTheThings/zip/refs/heads/master"
SYNC_QUEUE = "siem:knowledge:sync"     # server-api pushes here for "Sync now"
STATE_KEY = "siem:knowledge:pat"       # status the Knowledge page shows
SYNC_LOCK = "siem:knowledge:sync-lock"
INDEX_LOCK = "siem:knowledge:index-lock"
INDEX_QUEUE = "siem:knowledge:index"   # server-api pushes entry ids when an article is saved

_SKIP_HEADINGS = re.compile(r"(?i)^(summary|table of contents|contents|references?|labs?|tools?|credits|thanks"
                            r"|challenges?|resources|methodology)$")
_HEADING = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$", re.M)


# ─── PayloadsAllTheThings parsing ────────────────────────────────

def parse_markdown_sections(path: str, md: str) -> list[dict]:
    """One reference entry per section that carries payloads (a code block or
    enough text): {"source_ref", "title", "content"}. `path` is relative to the
    repo root, e.g. "SQL Injection/MySQL Injection.md"."""
    parts = path.split("/")
    # top-level files (repo README, CONTRIBUTING, …) aren't payload pages; a category's README is its main page
    if len(parts) < 2 or parts[-1].startswith("_"):
        return []
    category = parts[0]
    page = parts[-1][:-3]
    page = "" if page.lower() == "readme" else page

    out = []
    matches = list(_HEADING.finditer(md))
    for i, m in enumerate(matches):
        heading = re.sub(r"[`*_]", "", m.group(2)).strip()
        if len(m.group(1)) == 1 or _SKIP_HEADINGS.match(heading):
            continue
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md)
        body = md[m.end():end].strip()
        if "```" not in body and len(body) < 120:
            continue
        title = " — ".join(p for p in (category, page, heading) if p)
        out.append({"source_ref": f"{path}#{heading}", "title": title[:300],
                    "content": f"{title}\n\n{body}"[:MAX_SECTION_CHARS]})
    return out


def parse_repo_zip(data: bytes) -> list[dict]:
    """Every payload section of a PayloadsAllTheThings zip."""
    entries, seen = [], set()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if not name.endswith(".md"):
                continue
            rel = name.split("/", 1)[1] if "/" in name else name  # drop "PayloadsAllTheThings-master/"
            if rel.startswith((".", "_")) or "/" not in rel:
                continue
            try:
                md = zf.read(name).decode("utf-8", errors="replace")
            except KeyError:
                continue
            for entry in parse_markdown_sections(rel, md):
                if entry["source_ref"] not in seen:
                    seen.add(entry["source_ref"])
                    entries.append(entry)
    return entries


async def _set_state(redis, **fields) -> None:
    await redis.hset(STATE_KEY, mapping={k: json.dumps(v) if not isinstance(v, str) else v for k, v in fields.items()})


async def sync_payloadsallthethings(redis, url: str) -> dict:
    """Download, parse and upsert; only changed sections get re-embedded."""
    import httpx

    await _set_state(redis, status="downloading", started=datetime.now(timezone.utc).isoformat(), error="")
    async with httpx.AsyncClient(timeout=300, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        if len(resp.content) > MAX_ZIP_BYTES:
            raise ValueError(f"archive is larger than {MAX_ZIP_BYTES >> 20} MB")
        data = resp.content
    await _set_state(redis, status="parsing")
    entries = parse_repo_zip(data)
    if not entries:
        raise ValueError("no payload sections found — is this the PayloadsAllTheThings archive?")

    stats = {"added": 0, "updated": 0, "removed": 0, "unchanged": 0}
    async with AsyncSessionLocal() as db:
        existing = {r["source_ref"]: (r["id"], r["content"]) for r in (await db.execute(text(
            "SELECT id::text AS id, source_ref, content FROM knowledge_entries WHERE source = :s"
        ), {"s": PAT_SOURCE})).mappings()}
        wanted = {e["source_ref"] for e in entries}
        for e in entries:
            old = existing.get(e["source_ref"])
            if old is None:
                await db.execute(text("""
                    INSERT INTO knowledge_entries (id, group_id, kind, source, source_ref, title, content, scope,
                                                   enabled, created_at, updated_at, trust, content_type)
                    VALUES (gen_random_uuid(), '*', 'reference', :s, :ref, :title, :content, '{}'::jsonb,
                            true, now(), now(), 'external', 'external_reference')
                """), {"s": PAT_SOURCE, "ref": e["source_ref"], "title": e["title"], "content": e["content"]})
                stats["added"] += 1
            elif old[1] != e["content"]:
                await db.execute(text(
                    "UPDATE knowledge_entries SET title = :title, content = :content, updated_at = now() "
                    "WHERE id = CAST(:id AS uuid)"), {"id": old[0], "title": e["title"], "content": e["content"]})
                stats["updated"] += 1
            else:
                stats["unchanged"] += 1
        gone = [eid for ref, (eid, _) in existing.items() if ref not in wanted]
        if gone:
            await db.execute(text("DELETE FROM knowledge_entries WHERE id = ANY(CAST(:ids AS uuid[]))"), {"ids": gone})
            stats["removed"] = len(gone)
        await db.commit()
    await _set_state(redis, status="ok", last_sync=datetime.now(timezone.utc).isoformat(),
                     entries=len(entries), **{k: v for k, v in stats.items()}, error="")
    log.info("knowledge_pat_synced", entries=len(entries), **stats)
    return stats


# ─── Indexing ────────────────────────────────────────────────────

def chunk_text(content: str, size: int = CHUNK_CHARS) -> list[str]:
    """Paragraph-aligned chunks; a single huge block is cut hard."""
    chunks, current = [], ""
    for para in re.split(r"\n\s*\n", content.strip()):
        if current and len(current) + len(para) + 2 > size:
            chunks.append(current)
            current = ""
        current = f"{current}\n\n{para}" if current else para
        while len(current) > size:
            chunks.append(current[:size])
            current = current[size:]
    if current.strip():
        chunks.append(current)
    return chunks


def _chunks(row) -> list[tuple[str | None, str]]:
    """Notes and vault articles split at their headings; reference sections by paragraph."""
    if row["kind"] == "note":
        return md.chunk_markdown(row["title"], row["content"])
    return [(None, c) for c in chunk_text(row["content"])]


async def index_pending(limit: int = INDEX_BATCH) -> int:
    """Embed published entries that are new or changed since they were last
    indexed. Drafts and archived articles never reach the AI, so they wait.
    An entry's old chunks are replaced only once the new ones embedded: if
    embedding fails, the previous published version stays searchable."""
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT id::text AS id, group_id, kind, title, content
            FROM knowledge_entries
            WHERE (indexed_at IS NULL OR indexed_at < updated_at) AND status = 'published'
            ORDER BY (kind = 'note') DESC, updated_at
            LIMIT :n
        """), {"n": limit})).mappings().all()
    if not rows:
        return 0
    ids = [r["id"] for r in rows]
    pieces = [(r, i, heading, c) for r in rows for i, (heading, c) in enumerate(_chunks(r))]
    try:
        vectors = await asyncio.to_thread(embed_texts, [c for *_, c in pieces], EMBED_BATCH)
    except Exception as exc:  # noqa: BLE001 — no model now; next round
        log.warning("knowledge_embed_failed", error=str(exc), entries=len(rows))
        async with AsyncSessionLocal() as db:  # shown on the article as its index status
            await db.execute(text("UPDATE knowledge_entries SET index_error = :e WHERE id = ANY(CAST(:ids AS uuid[]))"),
                             {"e": f"embedding failed: {exc}"[:500], "ids": ids})
            await db.commit()
        return 0
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM knowledge_chunks WHERE entry_id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids})
        for (r, i, heading, chunk), vec in zip(pieces, vectors):
            await db.execute(text("""
                INSERT INTO knowledge_chunks (id, entry_id, group_id, kind, chunk_index, chunk_text, heading, embedding)
                VALUES (gen_random_uuid(), CAST(:e AS uuid), :g, :k, :i, :t, :h, CAST(:v AS vector))
            """), {"e": r["id"], "g": r["group_id"], "k": r["kind"], "i": i, "t": chunk, "h": heading,
                   "v": str(vec)})
        await db.execute(text("UPDATE knowledge_entries SET indexed_at = now(), index_error = NULL "
                              "WHERE id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids})
        await db.commit()
    log.info("knowledge_indexed", entries=len(rows), chunks=len(pieces))
    return len(rows)


async def _sync_due(redis) -> bool:
    if await redis.lpop(SYNC_QUEUE):
        return True
    if (await get_setting("knowledge_pat_enabled", "true")).lower() == "false":
        return False
    last = await redis.hget(STATE_KEY, "last_sync")
    if not last:
        return True
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(last.strip('"'))
    except ValueError:
        return True
    return age.days >= SYNC_EVERY_DAYS


async def knowledge_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(120)  # after startup and the other indexers
    while True:
        try:
            redis = await get_redis()
            if await _sync_due(redis) and await redis.set(SYNC_LOCK, "1", nx=True, ex=3600):
                try:
                    url = (await get_setting("knowledge_pat_url", DEFAULT_PAT_URL)).strip() or DEFAULT_PAT_URL
                    await sync_payloadsallthethings(redis, url)
                except Exception as exc:  # noqa: BLE001 — shown on the Knowledge page
                    log.warning("knowledge_pat_sync_failed", error=str(exc))
                    await _set_state(redis, status="error", error=str(exc)[:500],
                                     last_attempt=datetime.now(timezone.utc).isoformat())
                finally:
                    await redis.delete(SYNC_LOCK)
            # one replica indexes at a time, or both embed the same entries twice
            if await redis.set(INDEX_LOCK, "1", nx=True, ex=INDEX_LOCK_TTL):
                try:
                    while await index_pending():
                        await redis.expire(INDEX_LOCK, INDEX_LOCK_TTL)
                finally:
                    await redis.delete(INDEX_LOCK)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.error("knowledge_loop_error", error=str(exc))
        await _wait_for_work()


async def _wait_for_work() -> None:
    """Until server-api saves an article (it pushes to INDEX_QUEUE) or LOOP_INTERVAL
    passes; the periodic pass also recovers anything a lost push missed."""
    from worker.redis_client import get_redis
    try:
        redis = await get_redis()
        if await redis.blpop(INDEX_QUEUE, timeout=LOOP_INTERVAL):
            await redis.delete(INDEX_QUEUE)  # one pass indexes every pending entry
            return
    except Exception:  # noqa: BLE001 — no Redis: fall back to polling
        await asyncio.sleep(LOOP_INTERVAL)


# ─── Triage hook ─────────────────────────────────────────────────

async def retrieve_for_alert(title: str, source_ip: str | None, hostname: str | None,
                             fields: dict | None, group_id: str) -> dict:
    """Notes about this alert's entities or topic, and payload reference for web/injection alerts."""
    async with AsyncSessionLocal() as db:
        return await query_knowledge(
            db, embed_or_none, alert_query_text(title, fields), group_id,
            alert_entities(source_ip, hostname, fields, title), wants_payload_reference(title, fields))
