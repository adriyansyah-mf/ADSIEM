from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from worker.consumer import MAX_INGEST_DLQ_RETRIES, dlq_retry_loop


class _FakePipeline:
    def __init__(self, recorder: list[tuple[str, str, dict]]) -> None:
        self._recorder = recorder

    def xadd(self, key: str, data: dict) -> None:
        self._recorder.append(("xadd", key, data))

    def xdel(self, key: str, entry_id: str) -> None:
        self._recorder.append(("xdel", key, {"entry_id": entry_id}))

    async def execute(self) -> None:
        return None


class _FakeRedis:
    def __init__(self, entries: list[tuple[str, dict]]) -> None:
        self._entries = entries
        self.recorder: list[tuple[str, str, dict]] = []

    async def xrange(self, key: str, count: int = 1):
        return self._entries

    def pipeline(self):
        return _FakePipeline(self.recorder)


async def _run_one_dlq_cycle(entries: list[tuple[str, dict]]) -> _FakeRedis:
    """Run exactly one iteration of dlq_retry_loop's body by cancelling the
    loop's sleep after the first pass."""
    import asyncio

    redis = _FakeRedis(entries)
    call_count = 0

    async def fake_sleep(_seconds: float) -> None:
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise asyncio.CancelledError()

    with (
        patch("worker.consumer.get_redis", new=AsyncMock(return_value=redis)),
        patch("worker.consumer.asyncio.sleep", new=fake_sleep),
    ):
        try:
            await dlq_retry_loop({})
        except asyncio.CancelledError:
            pass
    return redis


@pytest.mark.asyncio
async def test_message_under_retry_cap_is_reinjected_with_incremented_count() -> None:
    entries = [("1-0", {"raw_message": "x", "retry_count": "2"})]
    redis = await _run_one_dlq_cycle(entries)

    xadd_calls = [c for c in redis.recorder if c[0] == "xadd"]
    assert len(xadd_calls) == 1
    _, key, data = xadd_calls[0]
    assert key == "siem:logs"  # main stream, not :dead
    assert data["retry_count"] == "3"


@pytest.mark.asyncio
async def test_message_at_retry_cap_moves_to_dead_letter_not_reinjected() -> None:
    entries = [("1-0", {"raw_message": "x", "retry_count": str(MAX_INGEST_DLQ_RETRIES)})]
    redis = await _run_one_dlq_cycle(entries)

    xadd_calls = [c for c in redis.recorder if c[0] == "xadd"]
    assert len(xadd_calls) == 1
    _, key, data = xadd_calls[0]
    assert key == "siem:logs:dead"
    assert data["retry_count"] == str(MAX_INGEST_DLQ_RETRIES)  # unchanged, not incremented


@pytest.mark.asyncio
async def test_message_with_no_retry_count_defaults_to_zero_and_is_reinjected() -> None:
    entries = [("1-0", {"raw_message": "x"})]  # never-before-retried message
    redis = await _run_one_dlq_cycle(entries)

    xadd_calls = [c for c in redis.recorder if c[0] == "xadd"]
    assert len(xadd_calls) == 1
    _, key, data = xadd_calls[0]
    assert key == "siem:logs"
    assert data["retry_count"] == "1"


@pytest.mark.asyncio
async def test_every_entry_is_deleted_from_the_dlq_regardless_of_outcome() -> None:
    entries = [
        ("1-0", {"raw_message": "a", "retry_count": "0"}),
        ("2-0", {"raw_message": "b", "retry_count": str(MAX_INGEST_DLQ_RETRIES)}),
    ]
    redis = await _run_one_dlq_cycle(entries)

    xdel_calls = [c for c in redis.recorder if c[0] == "xdel"]
    assert len(xdel_calls) == 2
