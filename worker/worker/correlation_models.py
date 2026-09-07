from dataclasses import dataclass
from typing import Literal, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
CorrelationEvent: TypeAlias = dict[str, JsonValue]
CorrelationStage: TypeAlias = dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CorrelationDefinition:
    id: str
    mode: Literal["sequence", "threshold"]
    window_seconds: int
    group_by: tuple[str, ...]
    stages: tuple[CorrelationStage, ...]
    suppression_seconds: int = 0


@dataclass(frozen=True, slots=True)
class CorrelationMatch:
    correlation_key: str
    stage_count: int
    first_seen: float
    last_seen: float
    events: tuple[CorrelationEvent, ...]
