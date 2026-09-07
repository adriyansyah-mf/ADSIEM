import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from ipaddress import ip_address, ip_network
from typing import Final, TypeAlias, assert_never

from app.core.sigma_condition import SigmaRuleError, evaluate_condition, wildcard_regex

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class MatchOperator(StrEnum):
    EQUAL = "equal"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "re"
    EXISTS = "exists"
    CIDR = "cidr"


class _MissingValue(Enum):
    TOKEN = "missing"


FieldValue: TypeAlias = JsonValue | _MissingValue
_MISSING: Final = _MissingValue.TOKEN
_OPERATORS: Final = {
    operator.value: operator
    for operator in MatchOperator
    if operator is not MatchOperator.EQUAL
}
_SUPPORTED_MODIFIERS: Final = frozenset({*_OPERATORS, "all", "nocase"})


@dataclass(frozen=True, slots=True)
class FieldMatcher:
    field: str
    operator: MatchOperator
    require_all: bool
    nocase: bool


def validate_rule(rule: Mapping[str, JsonValue]) -> None:
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaRuleError("rule must have a detection mapping")

    selections: dict[str, bool] = {}
    for name, selection in detection.items():
        if name == "condition":
            continue
        _validate_selection(name, selection)
        selections[name] = False
    if not selections:
        raise SigmaRuleError("detection must define at least one selection")

    condition = detection.get("condition", "selection")
    if not isinstance(condition, str):
        raise SigmaRuleError("detection condition must be a string")
    _ = evaluate_condition(condition, selections)


def evaluate_rule(
    rule: Mapping[str, JsonValue], event: Mapping[str, JsonValue]
) -> bool:
    validate_rule(rule)
    detection = rule["detection"]
    if not isinstance(detection, dict):
        raise SigmaRuleError("rule must have a detection mapping")
    return match_detection(detection, event)


def match_detection(
    detection: Mapping[str, JsonValue], event: Mapping[str, JsonValue]
) -> bool:
    named: dict[str, bool] = {}
    for name, selection in detection.items():
        if name != "condition":
            named[name] = _evaluate_selection(selection, event)
    condition = detection.get("condition", "selection")
    if not isinstance(condition, str):
        raise SigmaRuleError("detection condition must be a string")
    return evaluate_condition(condition, named)


def _validate_selection(name: str, selection: JsonValue) -> None:
    if isinstance(selection, dict):
        _validate_field_map(name, selection)
        return
    if isinstance(selection, list) and selection:
        for item in selection:
            if not isinstance(item, dict):
                raise SigmaRuleError(
                    f"selection '{name}' must contain only mapping alternatives"
                )
            _validate_field_map(name, item)
        return
    raise SigmaRuleError(f"selection '{name}' must be a mapping or a list of mappings")


def _validate_field_map(name: str, fields: Mapping[str, JsonValue]) -> None:
    if not fields:
        raise SigmaRuleError(f"selection '{name}' must not be empty")
    for field_key, condition in fields.items():
        matcher = _parse_field_matcher(field_key)
        values = condition if isinstance(condition, list) else [condition]
        if not values or any(isinstance(value, (dict, list)) for value in values):
            raise SigmaRuleError(f"field '{field_key}' must contain scalar values")
        if matcher.require_all and not isinstance(condition, list):
            raise SigmaRuleError(
                f"modifier 'all' on '{field_key}' requires a list value"
            )
        _validate_operator_values(matcher, values)


def _validate_operator_values(
    matcher: FieldMatcher, values: Sequence[JsonValue]
) -> None:
    match matcher.operator:
        case MatchOperator.REGEX:
            for value in values:
                if not isinstance(value, str):
                    raise SigmaRuleError(
                        f"regex value for '{matcher.field}' must be a string"
                    )
                try:
                    _ = re.compile(value)
                except re.error as exc:
                    raise SigmaRuleError(
                        f"invalid regex for '{matcher.field}': {exc}"
                    ) from exc
        case MatchOperator.CIDR:
            for value in values:
                if not isinstance(value, str):
                    raise SigmaRuleError(
                        f"CIDR value for '{matcher.field}' must be a string"
                    )
                try:
                    _ = ip_network(value, strict=False)
                except ValueError as exc:
                    raise SigmaRuleError(
                        f"invalid CIDR for '{matcher.field}': {value}"
                    ) from exc
        case MatchOperator.EXISTS:
            if len(values) != 1 or not isinstance(values[0], bool):
                raise SigmaRuleError(
                    f"exists value for '{matcher.field}' must be boolean"
                )
        case (
            MatchOperator.EQUAL
            | MatchOperator.CONTAINS
            | MatchOperator.STARTSWITH
            | MatchOperator.ENDSWITH
        ):
            return
        case unreachable:
            assert_never(unreachable)


def _parse_field_matcher(field_key: str) -> FieldMatcher:
    field, *modifiers = field_key.split("|")
    if not field:
        raise SigmaRuleError("field name must not be empty")
    unknown = set(modifiers) - _SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaRuleError(f"unsupported modifier on '{field}': {min(unknown)}")
    operators = [_OPERATORS[value] for value in modifiers if value in _OPERATORS]
    if len(operators) > 1:
        raise SigmaRuleError(f"field '{field}' has multiple match modifiers")
    operator = operators[0] if operators else MatchOperator.EQUAL
    return FieldMatcher(field, operator, "all" in modifiers, "nocase" in modifiers)


def _evaluate_selection(selection: JsonValue, event: Mapping[str, JsonValue]) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(key, value, event) for key, value in selection.items())
    if isinstance(selection, list):
        return any(
            all(_match_field(key, value, event) for key, value in alternative.items())
            for alternative in selection
            if isinstance(alternative, dict)
        )
    return False


def _match_field(
    field_key: str, condition: JsonValue, event: Mapping[str, JsonValue]
) -> bool:
    matcher = _parse_field_matcher(field_key)
    field_value = _get_field(event, matcher.field)
    values = condition if isinstance(condition, list) else [condition]
    results = [_match_value(field_value, value, matcher) for value in values]
    return all(results) if matcher.require_all else any(results)


def _get_field(event: Mapping[str, JsonValue], field: str) -> FieldValue:
    if field in event:
        return event[field]
    decoded = event.get("decoded_fields")
    if isinstance(decoded, dict) and field in decoded:
        return decoded[field]
    return _MISSING


def _match_value(
    field_value: FieldValue, condition: JsonValue, matcher: FieldMatcher
) -> bool:
    match matcher.operator:
        case MatchOperator.EXISTS:
            return (
                field_value is not _MISSING and field_value is not None
            ) is condition
        case MatchOperator.CIDR:
            if field_value is _MISSING or isinstance(field_value, (dict, list)):
                return False
            try:
                return ip_address(str(field_value)) in ip_network(
                    str(condition), strict=False
                )
            except ValueError:
                return False
        case (
            MatchOperator.EQUAL
            | MatchOperator.CONTAINS
            | MatchOperator.STARTSWITH
            | MatchOperator.ENDSWITH
            | MatchOperator.REGEX
        ):
            if field_value is _MISSING or isinstance(field_value, dict):
                return False
            if isinstance(field_value, list):
                return any(
                    _match_scalar(value, condition, matcher) for value in field_value
                )
            return _match_scalar(field_value, condition, matcher)
        case unreachable:
            assert_never(unreachable)


def _match_scalar(
    value: JsonValue, condition: JsonValue, matcher: FieldMatcher
) -> bool:
    if isinstance(value, (dict, list)) or isinstance(condition, (dict, list)):
        return False
    if condition is None:
        return value is None

    actual = str(value)
    expected = str(condition)
    if matcher.nocase:
        actual = actual.casefold()
        expected = expected.casefold()

    match matcher.operator:
        case MatchOperator.EQUAL:
            return bool(re.fullmatch(wildcard_regex(expected), actual))
        case MatchOperator.CONTAINS:
            return expected in actual
        case MatchOperator.STARTSWITH:
            return actual.startswith(expected)
        case MatchOperator.ENDSWITH:
            return actual.endswith(expected)
        case MatchOperator.REGEX:
            flags = re.IGNORECASE if matcher.nocase else 0
            return bool(re.search(str(condition), str(value), flags=flags))
        case MatchOperator.EXISTS | MatchOperator.CIDR:
            raise SigmaRuleError(
                f"operator '{matcher.operator}' requires a specialized value"
            )
        case unreachable:
            assert_never(unreachable)
