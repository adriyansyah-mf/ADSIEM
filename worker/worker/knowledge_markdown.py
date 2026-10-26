# worker/worker/knowledge_markdown.py
"""Markdown articles for the knowledge vault: frontmatter, headings,
[[wikilinks]], slugs, a secret scan, checksums and heading-aware chunks.

Pure functions shared by server-api (saving, importing an Obsidian vault) and
the worker (indexing). server-api's image copies this file, so it depends on
nothing but PyYAML.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime

import yaml

CONTENT_TYPES = ("environment", "dfir_article", "sop", "detection", "incident_lesson", "external_reference")
TRUST_LEVELS = ("draft", "reviewed", "verified", "external")
STATUSES = ("draft", "published", "archived")
SCOPE_KEYS = ("ips", "hosts", "users", "rules")
CHUNK_CHARS = 1200

_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)
_FENCE = re.compile(r"^(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_WIKILINK = re.compile(r"(!?)\[\[([^\]\|#\n]*)(?:#([^\]\|\n]+))?(?:\|([^\]\n]+))?\]\]")
_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")

# High-confidence credential shapes only: DFIR articles legitimately show
# `password=` in examples, so a bare keyword is never enough.
_SECRETS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("credential assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|passw(?:or)?d)"
        r"\s*[:=]\s*['\"]?(?=[A-Za-z0-9/+_\-]*\d)(?=[A-Za-z0-9/+_\-]*[A-Za-z])[A-Za-z0-9/+_\-]{20,}")),
]


@dataclass
class Article:
    meta: dict
    body: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def slugify(text: str) -> str:
    """Obsidian-style link target → stable slug: 'Investigating PowerShell!' → 'investigating-powershell'."""
    s = re.sub(r"\.md$", "", (text or "").strip(), flags=re.I)
    s = re.sub(r"[^\w]+", "-", s.lower(), flags=re.UNICODE).strip("-_")
    return s[:200]


def _str_list(value, key: str, errors: list[str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\s]+", value) if v]
    if not isinstance(value, list) or not all(isinstance(v, (str, int, float)) for v in value):
        errors.append(f"{key} must be a list of strings")
        return []
    return [str(v).strip().lstrip("#") for v in value if str(v).strip()][:50]


def parse(markdown: str) -> Article:
    """Split and validate the frontmatter. Unknown keys (Obsidian adds many) are kept as they are."""
    markdown = (markdown or "").replace("\r\n", "\n")
    m = _FRONTMATTER.match(markdown)
    meta: dict = {}
    errors: list[str] = []
    warnings: list[str] = []
    body = markdown
    if m:
        body = markdown[m.end():]
        try:
            loaded = yaml.safe_load(m.group(1)) or {}
        except yaml.YAMLError as exc:
            return Article({}, body, [f"frontmatter is not valid YAML: {str(exc).splitlines()[0]}"])
        if not isinstance(loaded, dict):
            return Article({}, body, ["frontmatter must be a mapping of keys to values"])
        meta = {str(k): v for k, v in loaded.items()}
    if "title" in meta and not isinstance(meta["title"], (str, int, float)):
        errors.append("title must be text")
    for key in ("tags", "platforms", "aliases"):
        if key in meta:
            meta[key] = _str_list(meta[key], key, errors)
    if "mitre" in meta:
        meta["mitre"] = [t.upper() for t in _str_list(meta["mitre"], "mitre", errors)]
        bad = [t for t in meta["mitre"] if not _MITRE.match(t)]
        if bad:
            errors.append(f"mitre ids look like T1059 or T1059.001, not {', '.join(bad)}")
    if "trust" in meta and meta["trust"] not in TRUST_LEVELS:
        errors.append(f"trust must be one of {', '.join(TRUST_LEVELS)}")
    if "type" in meta and meta["type"] not in CONTENT_TYPES:
        errors.append(f"type must be one of {', '.join(CONTENT_TYPES)}")
    if "expires" in meta:
        value = meta["expires"]
        if isinstance(value, (date, datetime)):
            meta["expires"] = value.isoformat()
        else:
            try:
                meta["expires"] = date.fromisoformat(str(value)).isoformat()
            except ValueError:
                errors.append("expires must be a date like 2027-01-31")
    if "scope" in meta:
        scope = meta["scope"]
        if not isinstance(scope, dict):
            errors.append("scope must be a mapping (groups, ips, hosts, users, rules)")
        else:
            unknown = set(scope) - {"groups", *SCOPE_KEYS}
            if unknown:
                warnings.append(f"scope ignores {', '.join(sorted(unknown))}")
            meta["scope"] = {k: _str_list(scope.get(k), f"scope.{k}", errors) for k in ("groups", *SCOPE_KEYS)
                             if scope.get(k) is not None}
    # JSON-safe for storage (YAML dates and the like)
    meta = json.loads(json.dumps(meta, default=str))
    return Article(meta, body, errors, warnings)


def render(meta: dict, body: str) -> str:
    """The full Markdown an editor shows: frontmatter (if any) and body."""
    if not meta:
        return body
    return "---\n" + yaml.safe_dump(meta, sort_keys=False, allow_unicode=True).strip() + "\n---\n" + body


def _outside_fences(body: str):
    """Lines that are not inside a fenced code block, with their numbers."""
    fenced = False
    for i, line in enumerate(body.split("\n"), 1):
        if _FENCE.match(line.strip()):
            fenced = not fenced
            continue
        if not fenced:
            yield i, line


def headings(body: str) -> list[dict]:
    out = []
    for _, line in _outside_fences(body):
        m = _HEADING.match(line)
        if m:
            text = re.sub(r"[`*_]", "", m.group(2)).strip()
            out.append({"level": len(m.group(1)), "text": text, "anchor": slugify(text)})
    return out


def title_of(article: Article, fallback: str = "") -> str:
    """Frontmatter title, else the first H1, else the fallback (a file name)."""
    if str(article.meta.get("title") or "").strip():
        return str(article.meta["title"]).strip()[:300]
    for h in headings(article.body):
        if h["level"] == 1:
            return h["text"][:300]
    return re.sub(r"\.md$", "", fallback.rsplit("/", 1)[-1], flags=re.I).strip()[:300]


def wikilinks(body: str) -> list[dict]:
    """[[Target]], [[Target#Heading]], [[Target|alias]]; embeds (![[...]]) and links in code are skipped."""
    out, seen = [], set()
    for _, line in _outside_fences(body):
        for m in _WIKILINK.finditer(line):
            target = m.group(2).strip()
            if m.group(1) or not target:
                continue
            heading = (m.group(3) or "").strip() or None
            key = (slugify(target), heading)
            if key not in seen:
                seen.add(key)
                out.append({"target": target, "slug": slugify(target), "heading": heading})
    return out


def find_secrets(text: str) -> list[dict]:
    """Credential-shaped strings, with the line and a redacted excerpt (never the secret itself)."""
    found = []
    for i, line in enumerate((text or "").split("\n"), 1):
        for kind, pattern in _SECRETS:
            m = pattern.search(line)
            if m:
                value = m.group(0)
                found.append({"kind": kind, "line": i, "excerpt": value[:6] + "…" + f"({len(value)} chars)"})
    return found


def checksum(meta: dict, body: str) -> str:
    """Of what is stored: leading and trailing blank lines don't make a new version."""
    return hashlib.sha256(json.dumps([meta, body.strip("\n")], sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _paragraph_chunks(text: str, size: int) -> list[str]:
    chunks, current = [], ""
    for para in re.split(r"\n\s*\n", text.strip()):
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


def chunk_markdown(title: str, body: str, size: int = CHUNK_CHARS) -> list[tuple[str | None, str]]:
    """(heading, text) chunks split at H1–H3 sections, then by paragraph. Each
    chunk starts with the title and heading so it means something on its own."""
    sections: list[tuple[str | None, list[str]]] = [(None, [])]
    fenced = False
    for line in body.split("\n"):
        if _FENCE.match(line.strip()):
            fenced = not fenced
        m = None if fenced else _HEADING.match(line)
        if m and len(m.group(1)) <= 3:
            sections.append((re.sub(r"[`*_]", "", m.group(2)).strip(), []))
        else:
            sections[-1][1].append(line)
    out = []
    for heading, lines in sections:
        text = "\n".join(lines).strip()
        if not text:
            continue
        prefix = f"{title}\n{heading}\n" if heading else f"{title}\n"
        out += [(heading, prefix + piece) for piece in _paragraph_chunks(text, size - len(prefix))]
    return out or [(None, title)]
