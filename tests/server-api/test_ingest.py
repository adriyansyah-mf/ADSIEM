import pytest
from unittest.mock import AsyncMock
from app.services.ingest import enqueue_log

@pytest.mark.asyncio
async def test_enqueue_log_calls_xadd():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock(return_value="1234567890-0")
    payload = {
        "agent_id": "abc-123",
        "log_type": "linux_auth",
        "raw_message": "Failed password for root",
        "received_at": "2026-05-21T10:00:00+00:00",
        "hostname": "host1",
    }
    result = await enqueue_log(mock_redis, payload)
    assert result == "1234567890-0"
    mock_redis.xadd.assert_called_once()
    call_args = mock_redis.xadd.call_args
    assert call_args[0][0] == "siem:logs"
