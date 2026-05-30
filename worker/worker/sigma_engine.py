# worker/worker/sigma_engine.py
import re
import time
import uuid as _uuid
import yaml
from dataclasses import dataclass
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
    def __init__(self, redis=None):
        self._rules: list[RuleDef] = []
        self._redis = redis
        # In-memory fallback (single-process only)
        self._local_hits: dict[str, list[float]] = {}
        self._local_suppressed: dict[str, float] = {}

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

    async def evaluate(self, event: dict[str, Any]) -> list[dict]:
        now = time.time()
        matches = []
        for rule in self._rules:
            if not self._detection_matches(rule.detection, event):
                continue

            corr_result = None
            if rule.threshold:
                corr_result = await self._check_threshold(rule, event, now)
                if corr_result is None:
                    continue

            if rule.suppression:
                sup_key = f"siem:suppress:{rule.id}:{event.get('source.ip', '_')}"
                sup_window = rule.suppression.get("timewindow", 3600)
                if not await self._acquire_suppression(sup_key, sup_window):
                    continue

            title = rule.title
            match: dict[str, Any] = {
                "id": rule.id,
                "title": title,
                "level": rule.level,
                "tags": rule.tags,
                "mitre_tags": rule.mitre_tags,
            }
            if corr_result:
                hit_count, group_val = corr_result
                tw = rule.threshold.get("timewindow", 300)  # type: ignore[union-attr]
                suffix = f" from {group_val}" if group_val != "_all" else ""
                match["title"] = f"{title} [{hit_count}x in {tw}s{suffix}]"
                match["correlation_hit_count"] = hit_count
                match["correlation_group"] = group_val
            matches.append(match)
        return matches

    async def _check_threshold(
        self, rule: RuleDef, event: dict, now: float
    ) -> tuple[int, str] | None:
        """Returns (hit_count, group_val) when threshold is crossed, else None."""
        th = rule.threshold  # type: ignore[union-attr]
        required = int(th.get("count", 1))
        window = int(th.get("timewindow", 300))
        cooldown = int(th.get("cooldown", 0))
        group_by = th.get("group_by")
        group_val = str(event.get(group_by, "_all")) if group_by else "_all"

        hit_key = f"sigma:th:{rule.id}:{group_val}"
        cd_key = f"sigma:cd:{rule.id}:{group_val}"

        if self._redis:
            # Sorted-set sliding window: score = timestamp, member = unique id
            member = str(_uuid.uuid4())
            await self._redis.zadd(hit_key, {member: now})
            await self._redis.zremrangebyscore(hit_key, 0, now - window)
            await self._redis.expire(hit_key, window + 60)
            hit_count: int = await self._redis.zcard(hit_key)

            if hit_count < required:
                return None

            if cooldown > 0:
                if await self._redis.exists(cd_key):
                    return None  # still cooling down
                await self._redis.setex(cd_key, cooldown, "1")

            return (hit_count, group_val)
        else:
            hits = self._local_hits.setdefault(hit_key, [])
            hits.append(now)
            hits[:] = [t for t in hits if now - t <= window]
            if len(hits) < required:
                return None
            return (len(hits), group_val)

    async def _acquire_suppression(self, key: str, window: int) -> bool:
        """Returns True (fire) on first call; False while suppressed."""
        if self._redis:
            # Atomic SET NX: returns None if key already exists
            result = await self._redis.set(key, "1", nx=True, ex=window)
            return result is not None
        else:
            now = time.time()
            if key in self._local_suppressed and now < self._local_suppressed[key]:
                return False
            self._local_suppressed[key] = now + window
            return True

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
