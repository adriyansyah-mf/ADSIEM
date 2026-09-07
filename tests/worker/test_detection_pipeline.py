import os
import sys
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../server-api"))

from worker.correlation_engine import CorrelationEngine
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
        return results

    async def reset(self) -> None:
        self.commands.clear()


class LoginDecoder:
    def decode(self, log_type: str, raw_message: str) -> dict[str, str]:
        del log_type
        return {
            "event.category": "authentication",
            "event.action": raw_message,
            "source.ip": "10.0.0.5",
            "user.name": "alice",
        }


class SuccessSigma:
    rule_id = uuid.uuid4()

    async def evaluate(self, event: dict[str, str]) -> list[dict]:
        if event["event.action"] != "login_success":
            return []
        return [{
            "id": self.rule_id,
            "title": "Failed logins followed by success",
            "level": "high",
            "matched_fields": event,
            "sigma_rule": {"id": str(self.rule_id), "title": "Auth takeover"},
        }]


@pytest.mark.asyncio
async def test_five_failed_logins_then_success_emit_one_provenanced_alert() -> None:
    # Given
    from worker.consumer import process_message

    sigma = SuccessSigma()
    definition = CorrelationDefinition(
        id=str(sigma.rule_id),
        mode="sequence",
        window_seconds=60,
        group_by=("source.ip", "user.name"),
        stages=(
            *({"event.action": "login_failed"},) * 5,
            {"event.action": "login_success"},
        ),
        suppression_seconds=30,
    )
    create_alert = AsyncMock()
    messages = ["login_failed"] * 5 + ["login_success"]

    # When
    with (
        patch("worker.consumer.index_log", new=AsyncMock()),
        patch("worker.consumer.create_alert", new=create_alert),
        patch("worker.consumer.get_redis", new=AsyncMock()),
        patch("worker.consumer.ueba_score_event", new=AsyncMock()),
    ):
        for index, action in enumerate(messages):
            await process_message(
                {
                    "group_id": "tenant-a",
                    "hostname": "auth-1",
                    "log_type": "auth",
                    "raw_message": action,
                    "received_at": f"2026-09-06T12:00:0{index}+00:00",
                },
                LoginDecoder(),
                sigma,
                (CorrelationEngine(MemoryRedis()), (definition,)),
            )

    # Then
    create_alert.assert_awaited_once()
    match = create_alert.await_args.kwargs["rule_match"]
    assert match["correlation_id"] == str(sigma.rule_id)
    assert match["correlation_key"].startswith(
        f"correlation:tenant-a:{sigma.rule_id}:"
    )
    assert len(match["source_event_ids"]) == 6
    assert match["sigma_rule"]["id"] == str(sigma.rule_id)


@pytest.mark.asyncio
async def test_duplicate_correlation_key_is_suppressed_within_owning_group() -> None:
    # Given
    from worker.alert_manager import create_alert

    existing = SimpleNamespace(id=uuid.uuid4(), duplicate_count=0)
    result = MagicMock()
    result.scalar_one_or_none.return_value = existing
    db = AsyncMock()
    db.execute.return_value = result
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False

    # When
    with (
        patch("worker.alert_manager.AsyncSessionLocal", return_value=db),
        patch(
            "worker.alert_manager._is_suppressed",
            new=AsyncMock(return_value=False),
        ),
    ):
        alert_id = await create_alert(
            rule_match={
                "id": str(uuid.uuid4()),
                "title": "Correlated authentication activity",
                "level": "high",
                "correlation_id": "auth-sequence",
                "correlation_key": "correlation:tenant-a:auth-sequence:key",
                "source_event_ids": [str(uuid.uuid4())],
                "sigma_rule": {"id": str(uuid.uuid4())},
            },
            event_id=uuid.uuid4(),
            agent_id=None,
            group_id="tenant-a",
            source_ip="10.0.0.5",
            hostname="auth-1",
        )

    # Then
    assert alert_id == existing.id
    assert existing.duplicate_count == 1
    query = str(db.execute.await_args.args[0])
    assert "alerts.group_id" in query
    assert "alerts.correlation_key" in query


@pytest.mark.asyncio
async def test_case_timeline_hides_foreign_group_provenance() -> None:
    # Given
    from app.api.routes.cases import case_timeline

    no_case = MagicMock()
    no_case.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = no_case

    # When
    with pytest.raises(HTTPException) as error:
        await case_timeline(
            str(uuid.uuid4()),
            db=db,
            group_filter="tenant-b",
        )

    # Then
    assert error.value.status_code == 404
    query = str(db.execute.await_args.args[0])
    assert "cases.group_id" in query
