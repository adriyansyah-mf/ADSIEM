# worker/worker/knowledge_query.py
"""Retrieval over the knowledge base (knowledge_entries / knowledge_chunks).

Shared by the worker's triage and server-api (search_knowledge tool, the
Knowledge page preview) — server-api's image copies this file, so it only
depends on SQLAlchemy.

- Analyst notes whose scope names one of the alert's IPs, hosts, users or its
  rule match exactly. Embeddings are poor at telling one IP from another, and
  this part works even when the embedding model is unavailable.
- Notes and reference material (PayloadsAllTheThings) also match by meaning
  (embeddings) and by words (PostgreSQL full text), so retrieval still works
  when the embedding model is unavailable. Reference material is only pulled
  for alerts about web or injection attacks, where comparing the request with
  known payload techniques helps.
- Scores are weighted by trust (verified > reviewed > external > draft) and
  recency, can be narrowed by tags, type, platform and MITRE technique, and
  the best notes pull in their one-hop [[wikilink]] neighbours.
- Only published, enabled, unexpired entries are ever returned.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Awaitable, Callable

from sqlalchemy import text

NOTE_MIN_SCORE = 0.55        # cosine similarity a chunk needs on its own
REFERENCE_MIN_SCORE = 0.50
FTS_MIN_SCORE = 0.30         # normalized full-text rank a chunk needs on its own
MAX_EXACT_NOTES = 5
MAX_LINKED = 2               # one-hop neighbours added beyond max_notes
LINK_FACTOR = 0.5            # a neighbour's score relative to the note that links it
TRUST_WEIGHT = {"verified": 1.0, "reviewed": 0.9, "external": 0.75, "draft": 0.5}

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


_LIVE = "e.enabled AND (e.expires_at IS NULL OR e.expires_at > now()) AND e.status = 'published'"
_GROUP = "(CAST(:g AS text) IS NULL OR e.group_id IN (:g, '*'))"
_ENTRY_COLS = "e.id::text AS id, e.title, e.content, e.slug, e.version, e.trust, e.updated_at, e.source_ref"


# an OR query over the 'simple' configuration would match nearly everything on these
_STOPWORDS = {
    "the", "and", "for", "from", "with", "that", "this", "was", "were", "are", "has", "have", "had", "not", "but",
    "into", "onto", "over", "after", "before", "when", "what", "which", "who", "how", "why", "our", "your", "its",
    "yang", "dan", "dari", "untuk", "dengan", "ini", "itu", "pada", "dalam", "tidak", "atau", "ada", "akan",
}


def fts_query(query: str) -> str | None:
    """Words of a query as an OR full-text query: alert text is long, and no
    article contains every word of it. None when nothing is left."""
    words = []
    for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,}", query or ""):
        w = re.sub(r"[^\w]", "", w.lower())
        if len(w) >= 3 and w not in words and w not in _STOPWORDS:
            words.append(w)
    return " | ".join(words[:16]) or None


def _filters(filters: dict | None) -> tuple[str, dict]:
    """Metadata narrowing: tags, content types, platforms, MITRE techniques (any of each)."""
    clauses, params = [], {}
    for key, sql in (("tags", "e.tags ?| CAST(:f_tags AS text[])"),
                     ("content_types", "e.content_type = ANY(CAST(:f_content_types AS text[]))"),
                     ("platforms", "e.frontmatter->'platforms' ?| CAST(:f_platforms AS text[])"),
                     ("mitre", "e.frontmatter->'mitre' ?| CAST(:f_mitre AS text[])")):
        values = [str(v).strip() for v in (filters or {}).get(key) or [] if str(v).strip()]
        if values:
            clauses.append(sql)
            params[f"f_{key}"] = [v.upper() for v in values] if key == "mitre" else values
    return "".join(f" AND {c}" for c in clauses), params


def recency_weight(updated_at: datetime | None) -> float:
    """1.0 for three months, then easing down to 0.8 at two years."""
    if updated_at is None:
        return 1.0
    days = (datetime.now(timezone.utc) - updated_at).total_seconds() / 86400
    return 1.0 if days <= 90 else max(0.8, 1.0 - 0.2 * (days - 90) / 640)


def _entry(r, **extra) -> dict:
    eid = r["id"]
    return {"id": eid, "title": r["title"], "content": r["content"], "slug": r["slug"], "version": r["version"],
            "trust": r["trust"], "link": f"/knowledge?article={eid}", **extra}


async def _ranked(db, kind: str, vector: list | None, tsq: str | None, group_id: str | None,
                  filter_sql: str, filter_params: dict, min_vector: float) -> list[dict]:
    """Entries of one kind ranked by their best chunk: embeddings and full text
    combined, then weighted by trust and recency."""
    best: dict[str, dict] = {}
    base = f"FROM knowledge_chunks c JOIN knowledge_entries e ON e.id = c.entry_id " \
           f"WHERE c.kind = :kind AND {_LIVE} AND {_GROUP}{filter_sql}"
    params = {"kind": kind, "g": group_id, **filter_params}
    if vector is not None:
        rows = (await db.execute(text(f"""
            SELECT {_ENTRY_COLS}, c.heading, c.chunk_text, 1 - (c.embedding <=> CAST(:v AS vector)) AS score
            {base} ORDER BY c.embedding <=> CAST(:v AS vector) LIMIT 20
        """), {**params, "v": str(vector)})).mappings().all()
        for r in rows:
            cur = best.setdefault(r["id"], {"row": r, "vector": 0.0, "fulltext": 0.0, "heading": r["heading"],
                                            "chunk": r["chunk_text"]})
            if float(r["score"]) > cur["vector"]:
                cur.update(vector=float(r["score"]), heading=r["heading"], chunk=r["chunk_text"])
    if tsq:
        rows = (await db.execute(text(f"""
            SELECT {_ENTRY_COLS}, c.heading, c.chunk_text, ts_rank_cd(c.tsv, to_tsquery('simple', :q)) AS rank
            {base} AND c.tsv @@ to_tsquery('simple', :q) ORDER BY rank DESC LIMIT 20
        """), {**params, "q": tsq})).mappings().all()
        for r in rows:
            rank = float(r["rank"])
            norm = rank / (rank + 0.1)
            cur = best.setdefault(r["id"], {"row": r, "vector": 0.0, "fulltext": 0.0, "heading": r["heading"],
                                            "chunk": r["chunk_text"]})
            if norm > cur["fulltext"]:
                cur["fulltext"] = norm
                if cur["vector"] == 0.0:
                    cur.update(heading=r["heading"], chunk=r["chunk_text"])
    out = []
    for c in best.values():
        if c["vector"] < min_vector and c["fulltext"] < FTS_MIN_SCORE:
            continue
        relevance = 0.65 * c["vector"] + 0.35 * c["fulltext"] if vector is not None else c["fulltext"]
        trust, recency = TRUST_WEIGHT.get(c["row"]["trust"], 0.75), recency_weight(c["row"]["updated_at"])
        out.append({**c, "score": relevance * trust * recency, "trust_w": trust, "recency": recency})
    return sorted(out, key=lambda c: c["score"], reverse=True)


def _scores(c: dict) -> dict:
    return {"vector": round(c["vector"], 3), "fulltext": round(c["fulltext"], 3), "trust": c["trust_w"],
            "recency": round(c["recency"], 3)}


async def _linked(db, ids: list[str], group_id: str | None, filter_sql: str, filter_params: dict) -> list[dict]:
    """Published notes one [[wikilink]] away from these, in either direction."""
    rows = (await db.execute(text(f"""
        SELECT DISTINCT ON (e.id) {_ENTRY_COLS},
               CASE WHEN l.source_id::text = ANY(CAST(:ids AS text[])) THEN l.source_id ELSE l.target_id END::text AS via
        FROM knowledge_links l
        JOIN knowledge_entries e
          ON e.id = CASE WHEN l.source_id::text = ANY(CAST(:ids AS text[])) THEN l.target_id ELSE l.source_id END
        WHERE (l.source_id::text = ANY(CAST(:ids AS text[])) OR l.target_id::text = ANY(CAST(:ids AS text[])))
          AND e.kind = 'note' AND e.id::text <> ALL(CAST(:ids AS text[])) AND {_LIVE} AND {_GROUP}{filter_sql}
        LIMIT 10
    """), {"ids": ids, "g": group_id, **filter_params})).mappings().all()
    return list(rows)


async def query_knowledge(db, embed: EmbedFn, query: str, group_id: str | None, entities: dict,
                          want_reference: bool, max_notes: int = 3, max_references: int = 2,
                          filters: dict | None = None, expand_links: bool = True) -> dict:
    """{"notes": [...], "references": [...]} relevant to an alert or a question.
    Each note carries its heading, version, trust, canonical link and how it scored."""
    notes: dict[str, dict] = {}
    filter_sql, filter_params = _filters(filters)
    ents = {k: _norm(entities.get(k) or []) for k in ("ips", "hosts", "users", "rules")}
    if any(ents.values()):
        rows = (await db.execute(text(f"""
            SELECT {_ENTRY_COLS}, e.scope
            FROM knowledge_entries e
            WHERE e.kind = 'note' AND {_LIVE} AND {_GROUP}{filter_sql}
              AND (e.scope->'ips' ?| CAST(:ips AS text[]) OR e.scope->'hosts' ?| CAST(:hosts AS text[])
                   OR e.scope->'users' ?| CAST(:users AS text[]) OR e.scope->'rules' ?| CAST(:rules AS text[]))
            ORDER BY e.updated_at DESC
            LIMIT :n
        """), {"g": group_id, "n": MAX_EXACT_NOTES, **ents, **filter_params})).mappings().all()
        for r in rows:
            scope = r["scope"] or {}
            matched = [f"{kind[:-1]} {v}" for kind in ("ips", "hosts", "users", "rules")
                       for v in (scope.get(kind) or []) if v in ents[kind]]
            notes[r["id"]] = _entry(r, matched=matched, heading=None, scores={"exact": 1.0})

    vector = await embed(query) if query else None
    tsq = fts_query(query)
    if len(notes) < max_notes and (vector is not None or tsq):
        for c in await _ranked(db, "note", vector, tsq, group_id, filter_sql, filter_params, NOTE_MIN_SCORE):
            if len(notes) >= max_notes:
                break
            if c["row"]["id"] not in notes:
                notes[c["row"]["id"]] = _entry(c["row"], heading=c["heading"], score=round(c["score"], 3),
                                               scores=_scores(c))
    if expand_links and notes:
        parents = {nid: n.get("score", 1.0) for nid, n in notes.items()}
        added = 0
        for r in await _linked(db, list(notes), group_id, filter_sql, filter_params):
            if added >= MAX_LINKED:
                break
            weight = TRUST_WEIGHT.get(r["trust"], 0.75) * recency_weight(r["updated_at"])
            score = parents.get(r["via"], 1.0) * LINK_FACTOR * weight
            notes[r["id"]] = _entry(r, heading=None, score=round(score, 3), linked_from=r["via"],
                                    scores={"link": LINK_FACTOR, "trust": TRUST_WEIGHT.get(r["trust"], 0.75)})
            added += 1

    references: list[dict] = []
    if want_reference and (vector is not None or tsq):
        for c in await _ranked(db, "reference", vector, tsq, group_id, "", {}, REFERENCE_MIN_SCORE):
            if len(references) >= max_references:
                break
            r = c["row"]
            references.append({"id": r["id"], "title": r["title"], "source_ref": r["source_ref"], "text": c["chunk"],
                               "score": round(c["score"], 3), "scores": _scores(c)})
    return {"notes": list(notes.values()), "references": references}
