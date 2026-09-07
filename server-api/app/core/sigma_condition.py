import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import final


@dataclass(frozen=True, slots=True)
class SigmaRuleError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def wildcard_regex(pattern: str) -> str:
    fragments = ["^"]
    position = 0
    while position < len(pattern):
        character = pattern[position]
        if character == "\\" and position + 1 < len(pattern):
            escaped = pattern[position + 1]
            if escaped in {"*", "?", "\\"}:
                fragments.append(re.escape(escaped))
                position += 2
                continue
        if character == "*":
            fragments.append(".*")
        elif character == "?":
            fragments.append(".")
        else:
            fragments.append(re.escape(character))
        position += 1
    fragments.append("$")
    return "".join(fragments)


def evaluate_condition(expression: str, selections: Mapping[str, bool]) -> bool:
    return _ConditionParser(expression, selections).parse()


@final
class _ConditionParser:
    """Mutable token cursor for one condition expression."""

    def __init__(self, expression: str, selections: Mapping[str, bool]) -> None:
        self._tokens: tuple[str, ...] = tuple(re.findall(r"\(|\)|[^\s()]+", expression))
        self._selections: Mapping[str, bool] = selections
        self._position: int = 0

    def parse(self) -> bool:
        if not self._tokens:
            raise SigmaRuleError("condition must not be empty")
        result = self._parse_or()
        if self._peek() is not None:
            raise SigmaRuleError(f"unexpected condition token: {self._peek()}")
        return result

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while self._peek_keyword("or"):
            _ = self._consume()
            right = self._parse_and()
            result = result or right
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while self._peek_keyword("and"):
            _ = self._consume()
            right = self._parse_not()
            result = result and right
        return result

    def _parse_not(self) -> bool:
        if self._peek_keyword("not"):
            _ = self._consume()
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        if self._peek() == "(":
            _ = self._consume()
            result = self._parse_or()
            self._expect(")")
            return result

        token = self._consume()
        if self._peek_keyword("of") and (token.casefold() == "all" or token.isdigit()):
            return self._parse_quantifier(token)
        if token not in self._selections:
            raise SigmaRuleError(f"unknown selection in condition: {token}")
        return self._selections[token]

    def _parse_quantifier(self, quantity: str) -> bool:
        self._expect("of")
        pattern = self._consume()
        if pattern.casefold() == "them":
            names = tuple(self._selections)
        else:
            matcher = re.compile(wildcard_regex(pattern))
            names = tuple(name for name in self._selections if matcher.fullmatch(name))
        if not names:
            raise SigmaRuleError(f"condition selector matched no selections: {pattern}")

        required = len(names) if quantity.casefold() == "all" else int(quantity)
        if required < 1 or required > len(names):
            raise SigmaRuleError(
                f"condition requires {required} of {len(names)} selections"
            )
        matched = sum(1 for name in names if self._selections[name])
        return matched >= required

    def _peek(self) -> str | None:
        if self._position >= len(self._tokens):
            return None
        return self._tokens[self._position]

    def _peek_keyword(self, keyword: str) -> bool:
        token = self._peek()
        return token is not None and token.casefold() == keyword

    def _consume(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaRuleError("unexpected end of condition")
        self._position += 1
        return token

    def _expect(self, expected: str) -> None:
        token = self._consume()
        if token.casefold() != expected.casefold():
            raise SigmaRuleError(f"expected '{expected}' in condition, got '{token}'")
