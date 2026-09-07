import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.correlation_engine import CorrelationEngine, load_correlation_definitions
from worker.correlation_models import CorrelationDefinition


class MemoryRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def pipeline(self, transaction: bool = True) -> "MemoryPipeline":
        del transaction
        return MemoryPipeline(self)


class MemoryPipeline:
    def __init__(self, redis: MemoryRedis) -> None:
        self.redis = redis
        self.commands: list[tuple[str, str, str | None]] = []

    async def watch(self, *keys: str) -> None:
        del keys

    async def get(self, key: str) -> str | None:
        return self.redis.values.get(key)

    def multi(self) -> None:
        return None

    def set(self, key: str, value: str, *, px: int) -> None:
        del px
        self.commands.append(("set", key, value))

    def delete(self, key: str) -> None:
        self.commands.append(("delete", key, None))

    async def execute(self) -> list[bool]:
        results: list[bool] = []
        for command, key, value in self.commands:
            if command == "set" and value is not None:
                self.redis.values[key] = value
            else:
                self.redis.values.pop(key, None)
            results.append(True)
        self.commands.clear()
        return results

    async def reset(self) -> None:
        self.commands.clear()


def test_load_correlation_definitions_from_platform_setting():
    definitions = load_correlation_definitions(
        '[{"id":"auth-sequence","mode":"sequence","window_seconds":60,'
        '"group_by":["source.ip"],"stages":[{"event.action":"failed"},'
        '{"event.action":"success"}],"suppression_seconds":10}]'
    )
    assert definitions[0].id == "auth-sequence"
    assert definitions[0].window_seconds == 60


def test_load_correlation_definitions_rejects_invalid_payload():
    with pytest.raises(ValueError, match="JSON array"):
        load_correlation_definitions("{}")


def _event(
    action: str,
    *,
    source_ip: str = "10.0.0.5",
    user_name: str = "alice",
    event_id: str = "evt-1",
) -> dict:
    return {
        "group_id": "tenant-a",
        "event_id": event_id,
        "source": {"ip": source_ip},
        "user": {"name": user_name},
        "event": {"action": action},
    }


@pytest.mark.asyncio
async def test_grouped_sequence_matches_only_events_with_the_same_group_values():
    # Given
    engine = CorrelationEngine(MemoryRedis())
    definition = CorrelationDefinition(
        id="failed-then-success",
        mode="sequence",
        window_seconds=60,
        group_by=("source.ip", "user.name"),
        stages=(
            {"event.action": "login_failed"},
            {"event.action": "login_success"},
        ),
    )

    # When
    first = await engine.evaluate(definition, _event("login_failed"), now=100.0)
    other_group = await engine.evaluate(
        definition,
        _event("login_success", source_ip="10.0.0.6"),
        now=101.0,
    )
    match = await engine.evaluate(
        definition,
        _event("login_success", event_id="evt-2"),
        now=102.0,
    )

    # Then
    assert first is None
    assert other_group is None
    assert match is not None
    assert match.correlation_key.startswith("correlation:tenant-a:failed-then-success:")
    assert match.stage_count == 2
    assert match.first_seen == 100.0
    assert match.last_seen == 102.0
    assert [event["event_id"] for event in match.events] == ["evt-1", "evt-2"]


@pytest.mark.asyncio
async def test_threshold_counts_one_matching_event_per_required_stage():
    # Given
    engine = CorrelationEngine(MemoryRedis())
    definition = CorrelationDefinition(
        id="three-failures",
        mode="threshold",
        window_seconds=30,
        group_by=("source.ip",),
        stages=(
            {"event.action": "login_failed"},
            {"event.action": "login_failed"},
            {"event.action": "login_failed"},
        ),
    )

    # When
    results = [
        await engine.evaluate(
            definition,
            _event("login_failed", event_id=f"evt-{index}"),
            now=100.0 + index,
        )
        for index in range(1, 4)
    ]

    # Then
    assert results[:2] == [None, None]
    assert results[2] is not None
    assert results[2].stage_count == 3


@pytest.mark.asyncio
async def test_sequence_discards_state_after_the_window_expires():
    # Given
    engine = CorrelationEngine(MemoryRedis())
    definition = CorrelationDefinition(
        id="short-window",
        mode="sequence",
        window_seconds=10,
        group_by=("source.ip",),
        stages=(
            {"event.action": "login_failed"},
            {"event.action": "login_success"},
        ),
    )

    # When
    await engine.evaluate(definition, _event("login_failed"), now=100.0)
    expired = await engine.evaluate(definition, _event("login_success"), now=111.0)
    await engine.evaluate(definition, _event("login_failed"), now=112.0)
    match = await engine.evaluate(definition, _event("login_success"), now=113.0)

    # Then
    assert expired is None
    assert match is not None
    assert match.first_seen == 112.0


@pytest.mark.asyncio
async def test_suppression_prevents_duplicate_match_until_cooldown_ends():
    # Given
    engine = CorrelationEngine(MemoryRedis())
    definition = CorrelationDefinition(
        id="suppressed-sequence",
        mode="sequence",
        window_seconds=30,
        group_by=("source.ip",),
        stages=(
            {"event.action": "login_failed"},
            {"event.action": "login_success"},
        ),
        suppression_seconds=10,
    )

    # When
    await engine.evaluate(definition, _event("login_failed"), now=100.0)
    first = await engine.evaluate(definition, _event("login_success"), now=101.0)
    await engine.evaluate(definition, _event("login_failed"), now=102.0)
    suppressed = await engine.evaluate(definition, _event("login_success"), now=103.0)
    await engine.evaluate(definition, _event("login_failed"), now=112.0)
    after_cooldown = await engine.evaluate(
        definition,
        _event("login_success"),
        now=113.0,
    )

    # Then
    assert first is not None
    assert suppressed is None
    assert after_cooldown is not None


@pytest.mark.asyncio
async def test_stored_event_payload_is_bounded():
    # Given
    engine = CorrelationEngine(MemoryRedis())
    definition = CorrelationDefinition(
        id="bounded-payload",
        mode="threshold",
        window_seconds=30,
        group_by=("source.ip",),
        stages=({"event.action": "login_failed"},),
    )
    event = _event("login_failed") | {"raw_message": "x" * 20_000}

    # When
    match = await engine.evaluate(definition, event, now=100.0)

    # Then
    assert match is not None
    assert len(json.dumps(match.events[0]).encode()) <= 4_096
    assert match.events[0]["event_id"] == "evt-1"
