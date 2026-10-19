# worker/worker/knowledge_query.py
"""Retrieval over the knowledge base (knowledge_entries / knowledge_chunks).

Shared by the worker's triage and server-api (search_knowledge tool, the
Knowledge page preview) — server-api's image copies this file, so it only
depends on SQLAlchemy.

- Analyst notes whose scope names one of the alert's IPs, hosts, users or its
  rule match exactly. Embeddings are poor at telling one IP from another, and
  this part works even when the embedding model is unavailable.
- Notes and reference material (PayloadsAllTheThings) also match by meaning.
  Reference material is only pulled for alerts about web or injection attacks,
  where comparing the request with known payload techniques helps.
"""
from __future__ import annotations

import re
from typing import Awaitable, Callable

from sqlalchemy import text

NOTE_MIN_SCORE = 0.55
REFERENCE_MIN_SCORE = 0.50
MAX_EXACT_NOTES = 5

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
_WORD_RE = re.compile(r"[A-Za-z0-9][\w.@$-]{2,}")
_WEB_TITLE = re.compile(
    r"(?i)inject|sqli|\bsql\b|xss|cross.site|ssrf|ssti|template|xxe|\blfi\b|\brfi\b|travers|upload|deserial"
    r"|webshell|web shell|\brce\b|log4|spring4|shellshock|redirect|crlf|nosql|ldap|graphql|xmlrpc|wordpress"
    r"|wp-|php|http|web|scanner|probe|exposure|sensitive file")
_WEB_FIELDS = ("url.path", "url.original", "url.full", "url.query", "http.request.method", "http.request.body",
               "user_agent.original", "cs-uri-stem", "cs-uri-query")
_QUERY_FIELDS = (*_WEB_FIELDS, "CommandLine", "process.command_line", "ScriptBlockText", "message")
_USER_FIELDS = ("user.name", "TargetUserName", "SubjectUserName", "User", "username")
_DEST_IP_FIELDS = ("destination.ip", "DestinationIp", "IpAddress", "dst_ip")

EmbedFn = Callable[[str], Awaitable["list[float] | None"]]


def _norm(values) -> list[str]:
    out = []
    for v in values:
        s = str(v or "").strip().lower()
        if s and s not in out and s not in ("-", "none", "null"):
            out.append(s)
    return out


def normalize_scope(scope: dict | None) -> dict:
    """Scopes are stored lower-cased so they match the lower-cased entities."""
    scope = scope or {}
    return {k: _norm(scope.get(k) or []) for k in ("ips", "hosts", "users", "rules")}


def alert_entities(source_ip: str | None, hostname: str | None, fields: dict | None, title: str) -> dict:
    fields = fields or {}
    return {
        "ips": _norm([source_ip, *(fields.get(f) for f in _DEST_IP_FIELDS)]),
        "hosts": _norm([hostname]),
        "users": _norm(fields.get(f) for f in _USER_FIELDS),
        "rules": _norm([title]),
    }


def text_entities(query: str) -> dict:
    """For free text (assistant questions, the preview box): IPs, and every word
    as a possible host or user name."""
    words = _norm(_WORD_RE.findall(query or ""))
    return {"ips": _norm(_IP_RE.findall(query or "")), "hosts": words, "users": words, "rules": _norm([query])}


def wants_payload_reference(title: str, fields: dict | None) -> bool:
    fields = fields or {}
    return bool(_WEB_TITLE.search(title or "")) or any(fields.get(f) for f in _WEB_FIELDS)


def alert_query_text(title: str, fields: dict | None) -> str:
    """What the alert is about, for semantic matching: its title plus the request
    or command that triggered it."""
    fields = fields or {}
    parts = [title or ""] + [f"{f}: {fields[f]}" for f in _QUERY_FIELDS if fields.get(f)]
    return "\n".join(parts)[:1500]


_LIVE = "e.enabled AND (e.expires_at IS NULL OR e.expires_at > now())"
_GROUP = "(CAST(:g AS text) IS NULL OR e.group_id IN (:g, '*'))"


async def query_knowledge(db, embed: EmbedFn, query: str, group_id: str | None, entities: dict,
                          want_reference: bool, max_notes: int = 3, max_references: int = 2) -> dict:
    """{"notes": [...], "references": [...]} relevant to an alert or a question."""
    notes: dict[str, dict] = {}
    ents = {k: _norm(entities.get(k) or []) for k in ("ips", "hosts", "users", "rules")}
    if any(ents.values()):
        rows = (await db.execute(text(f"""
            SELECT e.id::text AS id, e.title, e.content, e.scope
            FROM knowledge_entries e
            WHERE e.kind = 'note' AND {_LIVE} AND {_GROUP}
              AND (e.scope->'ips' ?| CAST(:ips AS text[]) OR e.scope->'hosts' ?| CAST(:hosts AS text[])
                   OR e.scope->'users' ?| CAST(:users AS text[]) OR e.scope->'rules' ?| CAST(:rules AS text[]))
            ORDER BY e.updated_at DESC
            LIMIT :n
        """), {"g": group_id, "n": MAX_EXACT_NOTES, **ents})).mappings().all()
        for r in rows:
            scope = r["scope"] or {}
            matched = [f"{kind[:-1]} {v}" for kind in ("ips", "hosts", "users", "rules")
                       for v in (scope.get(kind) or []) if v in ents[kind]]
            notes[r["id"]] = {"id": r["id"], "title": r["title"], "content": r["content"], "matched": matched}

    references: list[dict] = []
    vector = await embed(query) if query else None
    if vector is not None:
        v = str(vector)
        if len(notes) < max_notes:
            rows = (await db.execute(text(f"""
                SELECT e.id::text AS id, e.title, e.content, 1 - (c.embedding <=> CAST(:v AS vector)) AS score
                FROM knowledge_chunks c JOIN knowledge_entries e ON e.id = c.entry_id
                WHERE c.kind = 'note' AND {_LIVE} AND {_GROUP}
                ORDER BY c.embedding <=> CAST(:v AS vector)
                LIMIT 10
            """), {"v": v, "g": group_id})).mappings().all()
            for r in rows:
                if len(notes) >= max_notes:
                    break
                if r["score"] >= NOTE_MIN_SCORE and r["id"] not in notes:
                    notes[r["id"]] = {"id": r["id"], "title": r["title"], "content": r["content"],
                                      "score": round(float(r["score"]), 3)}
        if want_reference:
            rows = (await db.execute(text(f"""
                SELECT e.id::text AS id, e.title, e.source_ref, c.chunk_text,
                       1 - (c.embedding <=> CAST(:v AS vector)) AS score
                FROM knowledge_chunks c JOIN knowledge_entries e ON e.id = c.entry_id
                WHERE c.kind = 'reference' AND {_LIVE} AND {_GROUP}
                ORDER BY c.embedding <=> CAST(:v AS vector)
                LIMIT 10
            """), {"v": v, "g": group_id})).mappings().all()
            seen = set()
            for r in rows:
                if len(references) >= max_references:
                    break
                if r["score"] >= REFERENCE_MIN_SCORE and r["id"] not in seen:
                    seen.add(r["id"])
                    references.append({"id": r["id"], "title": r["title"], "source_ref": r["source_ref"],
                                       "text": r["chunk_text"], "score": round(float(r["score"]), 3)})
    return {"notes": list(notes.values()), "references": references}
