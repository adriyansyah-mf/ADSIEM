import hashlib
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol, Self
from urllib.parse import quote

from redis.exceptions import WatchError

from worker.correlation_models import (
    CorrelationDefinition,
    CorrelationEvent,
    CorrelationMatch,
    JsonValue,
)
from worker.sigma_matcher import match_detection

MAX_EVENT_BYTES: Final = 4_096
MAX_STORED_EVENTS: Final = 100


class CorrelationInputError(ValueError):
    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"correlation event requires {field}")


def load_correlation_definitions(raw: str) -> tuple[CorrelationDefinition, ...]:
    if not raw.strip():
        return ()
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise ValueError("correlation_definitions must be a JSON array")
    definitions: list[CorrelationDefinition] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("each correlation definition must be an object")
        stages = item.get("stages")
        group_by = item.get("group_by", [])
        if not isinstance(stages, list) or not stages or not all(isinstance(s, dict) for s in stages):
            raise ValueError("correlation stages must be a non-empty array of objects")
        if not isinstance(group_by, list) or not all(isinstance(field, str) for field in group_by):
            raise ValueError("correlation group_by must be an array of strings")
        mode = item.get("mode")
        if mode not in ("sequence", "threshold"):
            raise ValueError("correlation mode must be sequence or threshold")
        window_seconds = int(item.get("window_seconds", 300))
        suppression_seconds = int(item.get("suppression_seconds", 0))
        if not 1 <= window_seconds <= 86_400 or not 0 <= suppression_seconds <= 86_400:
            raise ValueError("correlation windows must be between 0 and 86400 seconds")
        definitions.append(CorrelationDefinition(
            id=str(item["id"]),
            mode=mode,
            window_seconds=window_seconds,
            group_by=tuple(group_by),
            stages=tuple(stages),
            suppression_seconds=suppression_seconds,
        ))
    return tuple(definitions)


class _Pipeline(Protocol):
    async def watch(self, *keys: str) -> None: ...

    async def get(self, key: str) -> str | bytes | None: ...

    def multi(self) -> None: ...

    def set(self, key: str, value: str, *, px: int) -> Self: ...

    def delete(self, key: str) -> Self: ...

    async def execute(self) -> list[JsonValue]: ...

    async def reset(self) -> None: ...


class CorrelationStore(Protocol):
    def pipeline(self, transaction: bool = True) -> _Pipeline: ...


@dataclass(frozen=True, slots=True)
class _State:
    count: int
    first_seen: float
    last_seen: float
    events: tuple[CorrelationEvent, ...]


class CorrelationEngine:
    def __init__(self, redis: CorrelationStore) -> None:
        self._redis = redis

    async def evaluate(
        self,
        definition: CorrelationDefinition,
        event: Mapping[str, JsonValue],
        now: float | None = None,
    ) -> CorrelationMatch | None:
        evaluated_at = time.time() if now is None else now
        correlation_key = _correlation_key(definition, event)
        state_key = f"{correlation_key}:state"
        suppression_key = f"{correlation_key}:suppression"

        while True:
            pipe = self._redis.pipeline(transaction=True)
            try:
                await pipe.watch(state_key, suppression_key)
                suppression = await pipe.get(suppression_key)
                if suppression is not None and float(suppression) > evaluated_at:
                    return None

                state = _load_state(await pipe.get(state_key))
                expired = (
                    state is not None
                    and evaluated_at - state.first_seen > definition.window_seconds
                )
                current = None if expired else state
                next_state = _advance(
                    definition,
                    event,
                    current,
                    evaluated_at,
                    correlation_key,
                )

                pipe.multi()
                if suppression is not None:
                    pipe.delete(suppression_key)
                match next_state:
                    case CorrelationMatch():
                        pipe.delete(state_key)
                        if definition.suppression_seconds > 0:
                            pipe.set(
                                suppression_key,
                                str(evaluated_at + definition.suppression_seconds),
                                px=definition.suppression_seconds * 1_000,
                            )
                    case _State():
                        remaining_ms = max(
                            1,
                            math.ceil(
                                (
                                    next_state.first_seen
                                    + definition.window_seconds
                                    - evaluated_at
                                )
                                * 1_000
                            ),
                        )
                        pipe.set(
                            state_key,
                            _dump_state(next_state),
                            px=remaining_ms,
                        )
                    case None:
                        if expired:
                            pipe.delete(state_key)
                await pipe.execute()
                return next_state if isinstance(next_state, CorrelationMatch) else None
            except WatchError:
                continue
            finally:
                await pipe.reset()


def _advance(
    definition: CorrelationDefinition,
    event: Mapping[str, JsonValue],
    state: _State | None,
    now: float,
    correlation_key: str,
) -> _State | CorrelationMatch | None:
    flat_event = _flatten_event(event)
    bounded_event = _bound_event(event)

    match definition.mode:
        case "sequence":
            count = 0 if state is None else state.count
            if _matches(definition.stages[count], flat_event):
                return _record(
                    definition, state, bounded_event, now, correlation_key
                )
            if count > 0 and _matches(definition.stages[0], flat_event):
                return _record(
                    definition, None, bounded_event, now, correlation_key
                )
            return state
        case "threshold":
            if any(_matches(stage, flat_event) for stage in definition.stages):
                return _record(
                    definition, state, bounded_event, now, correlation_key
                )
            return state


def _record(
    definition: CorrelationDefinition,
    state: _State | None,
    event: CorrelationEvent,
    now: float,
    correlation_key: str,
) -> _State | CorrelationMatch:
    count = 1 if state is None else state.count + 1
    first_seen = now if state is None else state.first_seen
    previous_events = () if state is None else state.events
    events = (*previous_events, event)[-MAX_STORED_EVENTS:]
    if count == len(definition.stages):
        return CorrelationMatch(
            correlation_key=correlation_key,
            stage_count=count,
            first_seen=first_seen,
            last_seen=now,
            events=events,
        )
    return _State(
        count=count,
        first_seen=first_seen,
        last_seen=now,
        events=events,
    )


def _matches(
    stage: Mapping[str, JsonValue], event: Mapping[str, JsonValue]
) -> bool:
    return match_detection(
        {"selection": dict(stage), "condition": "selection"},
        event,
    )


def _flatten_event(event: Mapping[str, JsonValue]) -> CorrelationEvent:
    flattened: CorrelationEvent = dict(event)

    def visit(prefix: str, value: JsonValue) -> None:
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            flattened[path] = child
            visit(path, child)

    for key, value in event.items():
        visit(key, value)
    return flattened


def _correlation_key(
    definition: CorrelationDefinition, event: Mapping[str, JsonValue]
) -> str:
    tenant = event.get("group_id", event.get("tenant_id"))
    if tenant is None or isinstance(tenant, (dict, list)):
        raise CorrelationInputError("group_id or tenant_id")
    flattened = _flatten_event(event)
    group_values = [flattened.get(field) for field in definition.group_by]
    group_payload = json.dumps(group_values, separators=(",", ":"), sort_keys=True)
    group_digest = hashlib.sha256(group_payload.encode()).hexdigest()[:20]
    return (
        f"correlation:{quote(str(tenant), safe='')}:{quote(definition.id, safe='')}:"
        f"{group_digest}"
    )


def _bound_event(event: Mapping[str, JsonValue]) -> CorrelationEvent:
    candidate = dict(event)
    if len(json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode()) <= MAX_EVENT_BYTES:
        return candidate
    summary: CorrelationEvent = {"_truncated": True}
    for key in ("event_id", "@timestamp", "group_id", "tenant_id"):
        value = event.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            summary[key] = value
    return summary


def _load_state(raw: str | bytes | None) -> _State | None:
    if raw is None:
        return None
    payload = json.loads(raw)
    return _State(
        count=int(payload["count"]),
        first_seen=float(payload["first_seen"]),
        last_seen=float(payload["last_seen"]),
        events=tuple(payload["events"]),
    )


def _dump_state(state: _State) -> str:
    return json.dumps(
        {
            "count": state.count,
            "first_seen": state.first_seen,
            "last_seen": state.last_seen,
            "events": state.events,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
