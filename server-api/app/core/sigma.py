# server-api/app/core/sigma.py
import re
from typing import Any

def _match_value(field_value: Any, condition_value: Any) -> bool:
    if field_value is None:
        return False
    fv = str(field_value)
    if isinstance(condition_value, list):
        return any(_match_value(field_value, v) for v in condition_value)
    cv = str(condition_value)
    return fv == cv

def _match_field(field_key: str, condition_value: Any, event: dict) -> bool:
    if "|" in field_key:
        field, modifier = field_key.split("|", 1)
    else:
        field, modifier = field_key, None

    field_value = event.get(field) or event.get("decoded_fields", {}).get(field)

    if isinstance(condition_value, list):
        return any(_match_field_with_modifier(field_value, v, modifier) for v in condition_value)
    return _match_field_with_modifier(field_value, condition_value, modifier)

def _match_field_with_modifier(field_value: Any, condition_value: Any, modifier: str | None) -> bool:
    if field_value is None:
        return False
    fv = str(field_value)
    cv = str(condition_value)
    if modifier is None:
        return fv == cv
    elif modifier == "contains":
        return cv in fv
    elif modifier == "startswith":
        return fv.startswith(cv)
    elif modifier == "endswith":
        return fv.endswith(cv)
    elif modifier == "re":
        return bool(re.search(cv, fv))
    return fv == cv

def _evaluate_selection(selection: dict, event: dict) -> bool:
    return all(_match_field(k, v, event) for k, v in selection.items())

def evaluate_rule(rule_def: dict, event: dict) -> bool:
    detection = rule_def.get("detection", {})
    condition_str = detection.get("condition", "selection")

    named_selections: dict[str, bool] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            named_selections[key] = _evaluate_selection(value, event)

    condition_str = condition_str.strip()
    return _eval_condition(condition_str, named_selections)

def _eval_condition(expr: str, selections: dict[str, bool]) -> bool:
    expr = expr.strip()
    if " or " in expr:
        parts = [p.strip() for p in expr.split(" or ")]
        return any(_eval_condition(p, selections) for p in parts)
    if " and " in expr:
        parts = [p.strip() for p in expr.split(" and ")]
        return all(_eval_condition(p, selections) for p in parts)
    if expr.startswith("not "):
        return not _eval_condition(expr[4:].strip(), selections)
    return selections.get(expr, False)
