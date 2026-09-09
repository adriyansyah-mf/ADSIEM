"""Restricted `{{ path | filter }}` resolution for SOAR node configuration.

Deliberately not a template engine and never `eval`: a general-purpose
evaluator would reintroduce the arbitrary-code-execution node the design
rejected, through a side door. Dotted-path lookup with a closed filter set
only — see the design doc, sections 5.4 and 10.
"""
from __future__ import annotations

import json
import re
from typing import Any

_EXPRESSION = re.compile(r"\{\{(.+?)\}\}", re.DOTALL)
_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_CALL = re.compile(r"^default\((.*)\)$", re.DOTALL)

_MISSING = object()


def _lookup(path: str, context: dict) -> Any:
    current: Any = context
    for segment in path.split("."):
        segment = segment.strip()
        if not _SEGMENT.match(segment) or segment.startswith("__"):
            raise ValueError(f"invalid path segment {segment!r}")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return _MISSING
    return current


def _parse_default_argument(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        pass
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    return raw


def _apply_filter(name: str, value: Any) -> Any:
    default_call = _DEFAULT_CALL.match(name)
    if default_call:
        fallback = _parse_default_argument(default_call.group(1))
        return fallback if value is _MISSING or value is None else value
    value = None if value is _MISSING else value
    match name:
        case "lower":
            return value.lower() if isinstance(value, str) else value
        case "upper":
            return value.upper() if isinstance(value, str) else value
        case "json":
            return json.dumps(value)
        case _:
            raise ValueError(f"unsupported filter {name!r}")


def _evaluate(expression: str, context: dict) -> Any:
    parts = [part.strip() for part in expression.split("|")]
    value = _lookup(parts[0], context)
    for filter_name in parts[1:]:
        value = _apply_filter(filter_name, value)
    return None if value is _MISSING else value


def resolve_value(template: Any, context: dict) -> Any:
    """Resolve one config value. Non-strings pass through untouched.

    A string that is exactly one expression keeps the resolved value's type,
    so an If node can compare numbers as numbers. The single-expression test
    is a span check rather than an anchored regex: `^\\s*\\{\\{(.+?)\\}\\}\\s*$`
    matches "{{a}} {{b}}" as one expression with the path `a}} {{b`.
    """
    if not isinstance(template, str):
        return template
    stripped = template.strip()
    matches = list(_EXPRESSION.finditer(stripped))
    if len(matches) == 1 and matches[0].span() == (0, len(stripped)):
        return _evaluate(matches[0].group(1), context)

    def _replace(match: re.Match[str]) -> str:
        resolved = _evaluate(match.group(1), context)
        return "" if resolved is None else str(resolved)

    return _EXPRESSION.sub(_replace, template)


def resolve_config(config: Any, context: dict) -> Any:
    """Recursively resolve every string in a node's configuration."""
    match config:
        case dict():
            return {key: resolve_config(value, context) for key, value in config.items()}
        case list():
            return [resolve_config(item, context) for item in config]
        case _:
            return resolve_value(config, context)
