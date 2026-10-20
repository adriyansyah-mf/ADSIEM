"""Condition evaluation for the Trigger and If nodes (pure, no I/O)."""
from __future__ import annotations

import re
from typing import Any

from worker.soar.template import lookup, render

_REGEX_INPUT_CAP = 10_000


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def matches_condition(cond: dict, ctx: dict) -> bool:
    operator = cond.get("operator", "eq")
    actual = lookup(ctx, str(cond.get("field", "")))
    value = render(cond.get("value"), ctx)

    if operator == "not_null":
        return actual not in (None, "", [], {})
    if operator == "is_null":
        return actual in (None, "", [], {})
    if actual is None:
        return operator == "neq"
    if operator == "eq":
        return str(actual).lower() == str(value).lower()
    if operator == "neq":
        return str(actual).lower() != str(value).lower()
    if operator in ("gte", "lte", "gt", "lt"):
        a, b = _num(actual), _num(value)
        if a is None or b is None:
            return False
        return {"gte": a >= b, "lte": a <= b, "gt": a > b, "lt": a < b}[operator]
    if operator == "in":
        options = value if isinstance(value, list) else [v.strip() for v in str(value).split(",")]
        return str(actual).lower() in [str(v).lower() for v in options]
    if operator == "contains":
        if isinstance(actual, list):
            return any(str(value).lower() in str(item).lower() for item in actual)
        return str(value).lower() in str(actual).lower()
    if operator == "regex":
        try:
            return re.search(str(value), str(actual)[:_REGEX_INPUT_CAP]) is not None
        except re.error:
            return False
    return False


def matches(block: dict, ctx: dict) -> bool:
    """`{"match": "all"|"any", "conditions": [...]}`; no conditions always matches."""
    conditions = block.get("conditions") or []
    if not conditions:
        return True
    results = (matches_condition(c, ctx) for c in conditions)
    return all(results) if block.get("match", "all") == "all" else any(results)
