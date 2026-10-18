# worker/worker/sigma_engine.py
"""Sigma rule evaluation for the detection pipeline.

Rules are compiled once on load into matcher closures; evaluate() runs them
against flat decoded events. Covers the Sigma detection spec — value modifiers,
wildcards, keyword and list-of-map selections, the full condition grammar — plus
Sigma v2 correlation rules (event_count / value_count / temporal), alongside the
platform's own `threshold` / `suppression` extensions.

A rule using syntax the engine can't evaluate is rejected at load time and
reported in `load_errors`, instead of loading fine and silently never matching.
"""
import base64
import fnmatch
import ipaddress
import operator
import re
import time
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import structlog
import yaml

log = structlog.get_logger()

Matcher = Callable[[dict], bool]


class RuleError(ValueError):
    """Rule syntax the engine can't evaluate."""


# ─── Field access ────────────────────────────────────────────────

_MISSING = object()


def _lookup(event: dict, name: str) -> Any:
    """Flat dotted key first (what decoders emit), then a nested-dict walk."""
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _values(value: Any) -> list:
    if value is _MISSING or value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v is not None]
    return [value]


def _to_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


# ─── Value modifiers ─────────────────────────────────────────────

_MATCH_KINDS = ("contains", "startswith", "endswith")
_TRANSFORMS = {"wide", "utf16le", "utf16be", "utf16", "base64", "base64offset", "windash"}
_COMPARE = {"lt": operator.lt, "lte": operator.le, "gt": operator.gt, "gte": operator.ge}
_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_KNOWN_MODIFIERS = (
    set(_MATCH_KINDS) | _TRANSFORMS | set(_COMPARE) | set(_RE_FLAGS)
    | {"all", "re", "cidr", "exists", "cased", "fieldref"}
)
_DASHES = ("-", "/", "–", "—", "―")
_WINDASH_RE = re.compile(r"\B[-/]\b")


def _as_bytes(value: Any) -> bytes:
    return value if isinstance(value, bytes) else _to_str(value).encode()


def _base64offset(value: bytes) -> list[str]:
    # The three alignments a substring can take inside a larger base64 blob,
    # with the boundary characters that depend on neighbouring bytes trimmed.
    starts, ends = (0, 2, 3), (None, -3, -2)
    return [
        base64.b64encode(i * b" " + value)[starts[i]:ends[(len(value) + i) % 3]].decode()
        for i in range(3)
    ]


def _apply_transforms(value: Any, mods: list[str]) -> list[str]:
    values: list[Any] = [value]
    for mod in mods:
        if mod in ("wide", "utf16le"):
            values = [_to_str(v).encode("utf-16le") for v in values]
        elif mod == "utf16be":
            values = [_to_str(v).encode("utf-16be") for v in values]
        elif mod == "utf16":
            values = [b"\xff\xfe" + _to_str(v).encode("utf-16le") for v in values]
        elif mod == "base64":
            values = [base64.b64encode(_as_bytes(v)).decode() for v in values]
        elif mod == "base64offset":
            values = [s for v in values for s in _base64offset(_as_bytes(v))]
        elif mod == "windash":
            values = [
                variant
                for v in values
                for variant in dict.fromkeys(_WINDASH_RE.sub(d, _to_str(v)) for d in _DASHES)
            ]
    return [_to_str(v) for v in values]


def _wildcard_regex(pattern: str, kind: str, cased: bool) -> re.Pattern:
    # Sigma wildcards: * and ?; a backslash escapes only *, ? and itself.
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if kind in ("contains", "endswith"):
        body = ".*" + body
    if kind in ("contains", "startswith"):
        body += ".*"
    return re.compile(body, re.DOTALL | (0 if cased else re.IGNORECASE))


def _string_matcher(pattern: str, kind: str, cased: bool) -> Callable[[str], bool]:
    if not any(ch in pattern for ch in "*?\\"):
        p = pattern if cased else pattern.lower()
        norm: Callable[[str], str] = (lambda s: s) if cased else str.lower
        if kind == "contains":
            return lambda s: p in norm(s)
        if kind == "startswith":
            return lambda s: norm(s).startswith(p)
        if kind == "endswith":
            return lambda s: norm(s).endswith(p)
        return lambda s: norm(s) == p
    rx = _wildcard_regex(pattern, kind, cased)
    return lambda s: rx.fullmatch(s) is not None


def _value_predicate(value: Any, mods: list[str]) -> Callable[[str], bool]:
    """Predicate over one event value (as str) for one rule value."""
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(_to_str(value), strict=False)
        except ValueError as exc:
            raise RuleError(f"invalid cidr '{value}': {exc}") from exc

        def in_net(s: str) -> bool:
            try:
                return ipaddress.ip_address(s) in net
            except ValueError:
                return False
        return in_net

    if "re" in mods:
        flags = 0
        for mod in mods:
            flags |= _RE_FLAGS.get(mod, 0)
        try:
            rx = re.compile(_to_str(value), flags)
        except re.error as exc:
            raise RuleError(f"invalid regex '{value}': {exc}") from exc
        return lambda s: rx.search(s) is not None

    compare = [m for m in mods if m in _COMPARE]
    if compare:
        op = _COMPARE[compare[0]]
        try:
            bound = float(value)
        except (TypeError, ValueError) as exc:
            raise RuleError(f"'{compare[0]}' needs a number, got '{value}'") from exc

        def cmp(s: str) -> bool:
            try:
                return op(float(s), bound)
            except ValueError:
                return False
        return cmp

    kind = next((m for m in mods if m in _MATCH_KINDS), "equals")
    cased = "cased" in mods
    preds = [_string_matcher(p, kind, cased) for p in _apply_transforms(value, mods)]
    if len(preds) == 1:
        return preds[0]
    return lambda s: any(p(s) for p in preds)


def _compile_field(key: str, raw: Any) -> Matcher:
    name, *mods = key.split("|")
    unknown = [m for m in mods if m not in _KNOWN_MODIFIERS]
    if unknown:
        raise RuleError(f"unsupported modifier(s) {unknown} on '{key}'")
    if len([m for m in mods if m in _MATCH_KINDS]) > 1:
        raise RuleError(f"'{key}' combines more than one of contains/startswith/endswith")

    raw_values = raw if isinstance(raw, list) else [raw]

    if "exists" in mods:
        if len(raw_values) != 1 or not isinstance(raw_values[0], bool):
            raise RuleError(f"'{key}' needs true or false")
        want = raw_values[0]
        return lambda ev: (_lookup(ev, name) not in (_MISSING, None)) == want

    if "fieldref" in mods:
        if any(m in mods for m in (*_MATCH_KINDS, "re", "cidr", *_COMPARE)):
            raise RuleError(f"'{key}': fieldref only supports equality")
        refs = [_to_str(v) for v in raw_values]
        cased = "cased" in mods

        def ref_eq(ev: dict) -> bool:
            mine = [_to_str(v) for v in _values(_lookup(ev, name))]
            if not cased:
                mine = [v.lower() for v in mine]
            results = []
            for ref in refs:
                theirs = [_to_str(v) for v in _values(_lookup(ev, ref))]
                if not cased:
                    theirs = [v.lower() for v in theirs]
                results.append(bool(set(mine) & set(theirs)))
            return all(results) if "all" in mods else any(results)
        return ref_eq

    want_null = any(v is None for v in raw_values)
    preds = [_value_predicate(v, mods) for v in raw_values if v is not None]
    match_all = "all" in mods

    def match(ev: dict) -> bool:
        vals = _values(_lookup(ev, name))
        if not vals:
            return want_null
        if not preds:
            return False
        strs = [_to_str(v) for v in vals]
        hits = (any(p(s) for s in strs) for p in preds)
        return all(hits) if match_all else any(hits)
    return match


# ─── Selections & keywords ───────────────────────────────────────

# Keyword (field-less) searches look at the original log line when the event
# carries one, and fall back to every string field otherwise.
_KEYWORD_FIELDS = ("raw_message", "message", "event.original", "log.original")


def _compile_keyword(keyword: Any) -> Matcher:
    if isinstance(keyword, (dict, list)) or keyword is None:
        raise RuleError(f"invalid keyword {keyword!r}")
    pred = _string_matcher(_to_str(keyword), "contains", cased=False)

    def match(ev: dict) -> bool:
        texts = [ev[f] for f in _KEYWORD_FIELDS if isinstance(ev.get(f), str)]
        if not texts:
            texts = [v for v in ev.values() if isinstance(v, str)]
        return any(pred(t) for t in texts)
    return match


def _compile_selection(name: str, sel: Any) -> Matcher:
    if isinstance(sel, dict):
        if not sel:
            raise RuleError(f"selection '{name}' is empty")
        fields = [_compile_field(k, v) for k, v in sel.items()]
        return lambda ev: all(f(ev) for f in fields)
    if isinstance(sel, list):
        if not sel:
            raise RuleError(f"selection '{name}' is empty")
        # list of maps → OR of ANDs; list of scalars → keyword search
        items = [_compile_selection(name, i) if isinstance(i, dict) else _compile_keyword(i) for i in sel]
        return lambda ev: any(i(ev) for i in items)
    return _compile_keyword(sel)


# ─── Condition grammar ───────────────────────────────────────────
# expr := and ('or' and)* ; and := not ('and' not)* ; not := 'not' not | atom
# atom := '(' expr ')' | QUANT 'of' (NAME-glob | 'them') | NAME

class _ConditionParser:
    def __init__(self, expr: str, selections: dict[str, Matcher]):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", expr)
        self.pos = 0
        self.selections = selections

    def parse(self) -> Matcher:
        if not self.tokens:
            raise RuleError("condition is empty")
        matcher = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected '{self.tokens[self.pos]}' in condition")
        return matcher

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        if self.pos >= len(self.tokens):
            raise RuleError("condition ends unexpectedly")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self) -> Matcher:
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda ev: any(p(ev) for p in parts))

    def _and(self) -> Matcher:
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda ev: all(p(ev) for p in parts))

    def _not(self) -> Matcher:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda ev: not inner(ev)
        return self._atom()

    def _atom(self) -> Matcher:
        tok = self._peek()
        if tok == "(":
            self._take()
            inner = self._or()
            if self._peek() != ")":
                raise RuleError("missing ')' in condition")
            self._take()
            return inner
        if tok in (None, ")", "and", "or"):
            raise RuleError(f"expected a selection name, got '{tok or 'end of condition'}'")

        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._take().lower()
            self._take()
            target = self._take()
            if target.lower() == "them":
                names = [n for n in self.selections if not n.startswith("_")]
            else:
                names = [n for n in self.selections if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise RuleError(f"'{quant} of {target}' matches no selection")
            members = [self.selections[n] for n in names]
            if quant == "all":
                return lambda ev: all(m(ev) for m in members)
            if quant in ("1", "any"):
                return lambda ev: any(m(ev) for m in members)
            if quant.isdigit():
                need = int(quant)
                return lambda ev: sum(1 for m in members if m(ev)) >= need
            raise RuleError(f"unsupported quantifier '{quant} of'")

        name = self._take()
        if name not in self.selections:
            raise RuleError(f"condition references unknown selection '{name}'")
        return self.selections[name]


def _compile_detection(detection: Any) -> Matcher:
    if not isinstance(detection, dict):
        raise RuleError("'detection' must be a mapping")
    condition = detection.get("condition")
    if condition is None:
        raise RuleError("detection has no 'condition'")
    selections = {
        name: _compile_selection(name, sel)
        for name, sel in detection.items()
        if name not in ("condition", "timeframe")
    }
    conditions = condition if isinstance(condition, list) else [condition]
    compiled = []
    for cond in conditions:
        if not isinstance(cond, str):
            raise RuleError("condition must be a string")
        if "|" in cond:
            raise RuleError("aggregations in the condition ('| count() ...') are not supported; "
                            "use a correlation rule or the threshold block")
        compiled.append(_ConditionParser(cond, selections).parse())
    return compiled[0] if len(compiled) == 1 else (lambda ev: any(c(ev) for c in compiled))


def compile_detection(detection: Any) -> Matcher:
    """Compile a Sigma `detection` block into a predicate over a flat dict.

    Public entry point for callers that filter arbitrary rows rather than log
    events — live-response artifacts use it to filter collected rows. Raises
    RuleError on syntax the engine can't evaluate.
    """
    return _compile_detection(detection)


# ─── Rule definitions ────────────────────────────────────────────

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
    name: str | None = None
    matcher: Matcher = field(default=lambda ev: False, repr=False)
    db_id: str | None = None  # rules.id of the row this came from, so alerts link to their rule

    @property
    def refs(self) -> set[str]:
        """Identifiers a correlation rule may use to reference this rule."""
        return {r for r in (self.id, self.name, self.title) if r}


@dataclass
class CorrelationDef:
    id: str
    title: str
    level: str
    tags: list[str]
    mitre_tags: list[str]
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: int
    op: Callable[[float, float], bool] | None
    op_name: str
    bound: int
    value_field: str | None
    generate: bool
    db_id: str | None = None


_TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhdw]?)$")
_TIMESPAN_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_CORR_OPS = {"gt": operator.gt, "gte": operator.ge, "eq": operator.eq}


def _parse_timespan(raw: Any) -> int:
    m = _TIMESPAN_RE.match(str(raw).strip())
    if not m:
        raise RuleError(f"invalid timespan '{raw}' (use e.g. 30s, 5m, 1h, 1d)")
    return int(m.group(1)) * _TIMESPAN_UNITS[m.group(2)]


def _tags(d: dict) -> tuple[list[str], list[str]]:
    tags = d.get("tags") or []
    return tags, [t for t in tags if str(t).startswith("attack.")]


def _compile_rule(d: dict) -> RuleDef:
    if "detection" not in d:
        raise RuleError("rule has no 'detection' block")
    tags, mitre = _tags(d)
    return RuleDef(
        id=d.get("id", d.get("title", "unknown")),
        title=d.get("title", "Untitled"),
        level=d.get("level", "medium"),
        logsource=d.get("logsource", {}),
        detection=d["detection"],
        tags=tags,
        mitre_tags=mitre,
        threshold=d.get("threshold"),
        suppression=d.get("suppression"),
        name=d.get("name"),
        matcher=_compile_detection(d["detection"]),
    )


def _compile_correlation(d: dict) -> CorrelationDef:
    corr = d["correlation"]
    if not isinstance(corr, dict):
        raise RuleError("'correlation' must be a mapping")
    ctype = corr.get("type")
    if ctype not in ("event_count", "value_count", "temporal"):
        raise RuleError(f"unsupported correlation type '{ctype}' "
                        "(supported: event_count, value_count, temporal)")
    rules = corr.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not rules:
        raise RuleError("correlation needs 'rules'")
    group_by = corr.get("group-by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    if "timespan" not in corr:
        raise RuleError("correlation needs 'timespan'")

    op, op_name, bound, value_field = None, "", 0, None
    if ctype in ("event_count", "value_count"):
        cond = dict(corr.get("condition") or {})
        if ctype == "value_count":
            value_field = cond.pop("field", None)
            if not value_field:
                raise RuleError("value_count correlation needs condition.field")
        if len(cond) != 1:
            raise RuleError("correlation condition needs exactly one of gt, gte, eq")
        op_name, raw_bound = next(iter(cond.items()))
        if op_name not in _CORR_OPS:
            raise RuleError(f"correlation condition '{op_name}' is not supported "
                            "(lt/lte need a scheduled check; use gt, gte or eq)")
        op, bound = _CORR_OPS[op_name], int(raw_bound)

    tags, mitre = _tags(d)
    return CorrelationDef(
        id=d.get("id", d.get("name", d.get("title", "unknown"))),
        title=d.get("title", "Untitled correlation"),
        level=d.get("level", "medium"),
        tags=tags,
        mitre_tags=mitre,
        type=ctype,
        rules=[str(r) for r in rules],
        group_by=[str(g) for g in group_by],
        timespan=_parse_timespan(corr["timespan"]),
        op=op,
        op_name=op_name,
        bound=bound,
        value_field=value_field,
        generate=bool(corr.get("generate", False)),
    )


# ─── Engine ──────────────────────────────────────────────────────

class SigmaEngine:
    def __init__(self, redis=None):
        self._rules: list[RuleDef] = []
        self._correlations: list[CorrelationDef] = []
        self._silenced: set[str] = set()
        self.load_errors: list[tuple[str, str]] = []
        self._redis = redis
        # In-memory fallback (single-process only)
        self._local_hits: dict[str, list[float]] = {}
        self._local_suppressed: dict[str, float] = {}
        self._local_windows: dict[str, dict[str, float]] = {}

    def load_from_yaml_list(self, yaml_contents: list[str], rule_ids: list[str | None] | None = None) -> None:
        """rule_ids, aligned with yaml_contents, are the DB ids of the rule rows;
        matches carry them as rule_db_id."""
        rules: list[RuleDef] = []
        correlations: list[CorrelationDef] = []
        errors: list[tuple[str, str]] = []
        for idx, content in enumerate(yaml_contents):
            db_id = rule_ids[idx] if rule_ids and idx < len(rule_ids) else None
            try:
                docs = [doc for doc in yaml.safe_load_all(content) if doc]
            except yaml.YAMLError as exc:
                errors.append(("<unparseable YAML>", str(exc)))
                continue
            for doc in docs:
                title = doc.get("title", "Untitled") if isinstance(doc, dict) else "<invalid>"
                try:
                    if not isinstance(doc, dict):
                        raise RuleError("rule must be a YAML mapping")
                    if "correlation" in doc:
                        correlations.append(_compile_correlation(doc))
                        correlations[-1].db_id = db_id
                    else:
                        rules.append(_compile_rule(doc))
                        rules[-1].db_id = db_id
                except (RuleError, TypeError, ValueError) as exc:
                    errors.append((title, str(exc)))

        known = set().union(*(r.refs for r in rules)) if rules else set()
        valid_corrs = []
        for corr in correlations:
            missing = [ref for ref in corr.rules if ref not in known]
            if missing:
                errors.append((corr.title, f"correlation references unknown rule(s) {missing}"))
            else:
                valid_corrs.append(corr)

        self._rules = rules
        self._correlations = valid_corrs
        self._silenced = {ref for c in valid_corrs if not c.generate for ref in c.rules}
        self.load_errors = errors
        for title, err in errors:
            log.warning("sigma_rule_rejected", rule=title, error=err)

    async def evaluate(self, event: dict[str, Any]) -> list[dict]:
        now = time.time()
        fired: list[RuleDef] = []
        for rule in self._rules:
            try:
                if rule.matcher(event):
                    fired.append(rule)
            except Exception as exc:  # one bad rule must not drop the event for the rest
                log.warning("sigma_rule_eval_error", rule=rule.title, error=str(exc))

        matches = []
        for rule in fired:
            if rule.refs & self._silenced:
                continue  # only feeds a correlation with generate: false

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
                "rule_db_id": rule.db_id,
                "title": title,
                "level": rule.level,
                "tags": rule.tags,
                "mitre_tags": rule.mitre_tags,
            }
            if corr_result:
                hit_count, group_val = corr_result
                match["correlation_window"] = int(rule.threshold.get("timewindow", 300))  # type: ignore[union-attr]
                match["correlation_group_by"] = rule.threshold.get("group_by")  # type: ignore[union-attr]
                tw = rule.threshold.get("timewindow", 300)  # type: ignore[union-attr]
                suffix = f" from {group_val}" if group_val != "_all" else ""
                match["title"] = f"{title} [{hit_count}x in {tw}s{suffix}]"
                match["correlation_hit_count"] = hit_count
                match["correlation_group"] = group_val
            matches.append(match)

        if self._correlations and fired:
            fired_refs = set().union(*(r.refs for r in fired))
            for corr in self._correlations:
                hit_refs = [ref for ref in corr.rules if ref in fired_refs]
                if hit_refs:
                    corr_match = await self._check_correlation(corr, hit_refs, event, now)
                    if corr_match:
                        matches.append(corr_match)
        return matches

    async def _check_correlation(
        self, corr: CorrelationDef, hit_refs: list[str], event: dict, now: float
    ) -> dict | None:
        group_val = "|".join(
            _to_str(v) if (v := _lookup(event, g)) not in (_MISSING, None) else "_"
            for g in corr.group_by
        ) or "_all"
        key = f"sigma:corr:{corr.id}:{group_val}"

        if corr.type == "event_count":
            members = [str(_uuid.uuid4())]
        elif corr.type == "value_count":
            vals = _values(_lookup(event, corr.value_field))  # type: ignore[arg-type]
            if not vals:
                return None
            members = [_to_str(v) for v in vals]
        else:  # temporal: one member per referenced rule seen in the window
            members = hit_refs

        count = await self._window_add(key, members, now, corr.timespan)
        if corr.type == "temporal":
            fired = count >= len(set(corr.rules))
        else:
            fired = corr.op(count, corr.bound)  # type: ignore[misc]
        if not fired:
            return None
        await self._window_reset(key)  # start a fresh window instead of re-alerting on every event

        unit = {"event_count": "events", "value_count": f"distinct {corr.value_field}",
                "temporal": "correlated rules"}[corr.type]
        suffix = f" for {group_val}" if group_val != "_all" else ""
        return {
            "id": corr.id,
            "rule_db_id": corr.db_id,
            "title": f"{corr.title} [{count} {unit} in {corr.timespan}s{suffix}]",
            "level": corr.level,
            "tags": corr.tags,
            "mitre_tags": corr.mitre_tags,
            "correlation_hit_count": count,
            "correlation_group": group_val,
            "correlation_window": corr.timespan,
            "correlation_group_by": ", ".join(corr.group_by) or None,
            "correlation_type": corr.type,
            "correlation_rules": corr.rules,
        }

    async def _window_add(self, key: str, members: list[str], now: float, span: int) -> int:
        """Add members to a sliding window keyed set; return its size after trimming."""
        if self._redis:
            await self._redis.zadd(key, {m: now for m in members})
            await self._redis.zremrangebyscore(key, 0, now - span)
            await self._redis.expire(key, span + 60)
            return await self._redis.zcard(key)
        window = self._local_windows.setdefault(key, {})
        for m in members:
            window[m] = now
        for m in [m for m, ts in window.items() if now - ts > span]:
            del window[m]
        return len(window)

    async def _window_reset(self, key: str) -> None:
        if self._redis:
            await self._redis.delete(key)
        else:
            self._local_windows.pop(key, None)

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
