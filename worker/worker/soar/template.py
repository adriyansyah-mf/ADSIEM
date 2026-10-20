"""`{{ path }}` templates over the run context. Path lookup only — nothing is evaluated.

A path is dot-separated keys with optional list indexes: `steps.http_1.body.items[0].ip`.
Paths that don't start with a context root resolve against `trigger`, so the old
playbook field names (`severity`, `source_ip`) keep working.
"""
from __future__ import annotations

import json
import re
from typing import Any

ROOTS = ("trigger", "steps", "run", "secrets")

_TOKEN = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_MISSING = object()


class TemplateError(ValueError):
    pass


def parse_path(path: str) -> list[str | int]:
    path = (path or "").strip()
    if not path:
        raise TemplateError("empty path")
    parts: list[str | int] = []
    pos = 0
    for m in _PART.finditer(path):
        gap = path[pos:m.start()]
        if gap not in ("", "."):
            raise TemplateError(f"bad path: {path!r}")
        parts.append(int(m.group(2)) if m.group(2) is not None else m.group(1).strip())
        pos = m.end()
    if path[pos:] not in ("",):
        raise TemplateError(f"bad path: {path!r}")
    if not parts or isinstance(parts[0], int):
        raise TemplateError(f"bad path: {path!r}")
    return parts


def lookup(ctx: dict, path: str, default: Any = None) -> Any:
    """Value at `path` in ctx, or default when any segment is missing."""
    parts = parse_path(path)
    if parts[0] not in ROOTS:
        parts = ["trigger", *parts]
    cur: Any = ctx
    for p in parts:
        if isinstance(p, int):
            if isinstance(cur, list) and -len(cur) <= p < len(cur):
                cur = cur[p]
                continue
            return default
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
            continue
        return default
    return cur


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render(value: Any, ctx: dict) -> Any:
    """Render templates in a string, or recursively in a dict/list.

    A string that is exactly one `{{ path }}` keeps the value's type (number,
    dict, list); otherwise every token is replaced by its text form.
    """
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    if not isinstance(value, str) or "{{" not in value:
        return value
    whole = _TOKEN.fullmatch(value.strip())
    if whole:
        return lookup(ctx, whole.group(1))
    return _TOKEN.sub(lambda m: _to_text(lookup(ctx, m.group(1))), value)


def references(value: Any) -> list[str]:
    """Every path referenced by templates inside value (for validation)."""
    if isinstance(value, dict):
        return [p for v in value.values() for p in references(v)]
    if isinstance(value, list):
        return [p for v in value for p in references(v)]
    if isinstance(value, str):
        return [m.group(1) for m in _TOKEN.finditer(value)]
    return []
