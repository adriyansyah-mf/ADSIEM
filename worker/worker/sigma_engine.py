# worker/worker/sigma_engine.py
import re
import time
import yaml
from dataclasses import dataclass, field
from typing import Any

@dataclass
class RuleDef:
    id: str
    title: str
    level: str
    logsource: dict
    detection: dict
    tags: list[str]
    mitre_tags: list[str]
    threshold: dict | None
    suppression: dict | None

class SigmaEngine:
    def __init__(self):
        self._rules: list[RuleDef] = []
        self._threshold_hits: dict[str, list[float]] = {}
        self._suppressed: dict[str, float] = {}

    def load_from_yaml_list(self, yaml_contents: list[str]) -> None:
        rules = []
        for content in yaml_contents:
            try:
                d = yaml.safe_load(content)
                rules.append(RuleDef(
                    id=d.get("id", d.get("title", "unknown")),
                    title=d.get("title", "Untitled"),
                    level=d.get("level", "medium"),
                    logsource=d.get("logsource", {}),
                    detection=d.get("detection", {}),
                    tags=d.get("tags", []),
                    mitre_tags=[t for t in d.get("tags", []) if t.startswith("attack.")],
                    threshold=d.get("threshold"),
                    suppression=d.get("suppression"),
                ))
            except Exception:
                continue
        self._rules = rules

    def evaluate(self, event: dict[str, Any]) -> list[dict]:
        now = time.time()
        matches = []
        for rule in self._rules:
            if not self._detection_matches(rule.detection, event):
                continue
            if rule.threshold:
                if not self._check_threshold(rule, event, now):
                    continue
            if rule.suppression:
                suppress_key = self._suppression_key(rule, event)
                if suppress_key in self._suppressed:
                    if now < self._suppressed[suppress_key]:
                        continue
                window = rule.suppression.get("timewindow", 3600)
                self._suppressed[suppress_key] = now + window
            matches.append({
                "id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "tags": rule.tags,
                "mitre_tags": rule.mitre_tags,
            })
        return matches

    def _check_threshold(self, rule: RuleDef, event: dict, now: float) -> bool:
        th = rule.threshold
        count = th.get("count", 1)
        window = th.get("timewindow", 300)
        group_by = th.get("group_by")
        group_val = event.get(group_by, "_all") if group_by else "_all"
        key = f"{rule.id}:{group_val}"
        hits = self._threshold_hits.setdefault(key, [])
        hits.append(now)
        hits[:] = [t for t in hits if now - t <= window]
        return len(hits) >= count

    def _suppression_key(self, rule: RuleDef, event: dict) -> str:
        src_ip = event.get("source.ip", "unknown")
        return f"suppress:{rule.id}:{src_ip}"

    def _detection_matches(self, detection: dict, event: dict) -> bool:
        condition = detection.get("condition", "selection")
        named: dict[str, bool] = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                named[key] = self._evaluate_selection(value, event)
        return self._eval_condition(condition.strip(), named)

    def _evaluate_selection(self, selection: dict, event: dict) -> bool:
        return all(self._match_field(k, v, event) for k, v in selection.items())

    def _match_field(self, field_key: str, condition_value: Any, event: dict) -> bool:
        if "|" in field_key:
            field, modifier = field_key.split("|", 1)
        else:
            field, modifier = field_key, None
        field_value = event.get(field)
        if isinstance(condition_value, list):
            return any(self._apply_modifier(field_value, v, modifier) for v in condition_value)
        return self._apply_modifier(field_value, condition_value, modifier)

    def _apply_modifier(self, field_value: Any, condition_value: Any, modifier: str | None) -> bool:
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

    def _eval_condition(self, expr: str, selections: dict[str, bool]) -> bool:
        expr = expr.strip()
        if " or " in expr:
            return any(self._eval_condition(p.strip(), selections) for p in expr.split(" or "))
        if " and " in expr:
            return all(self._eval_condition(p.strip(), selections) for p in expr.split(" and "))
        if expr.startswith("not "):
            return not self._eval_condition(expr[4:].strip(), selections)
        return selections.get(expr, False)
