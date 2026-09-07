from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from redis.exceptions import RedisError

from app.core.rate_limit import (
    RATE_LIMIT_POLICIES,
    RateLimitPolicy,
    enforce_rate_limit,
)


# ── policy table shape ────────────────────────────────────────────


def test_all_plan_required_policies_are_declared() -> None:
    required = {
        "login", "mfa", "ingestion", "repository_import",
        "api_key_creation", "ai_chat", "soar_approval",
    }
    assert required <= RATE_LIMIT_POLICIES.keys()


def test_fail_open_closed_table_matches_documented_intent() -> None:
    # authentication and API-key creation fail closed (explicit in the plan)
    assert RATE_LIMIT_POLICIES["login"].fail_open is False
    assert RATE_LIMIT_POLICIES["mfa"].fail_open is False
    assert RATE_LIMIT_POLICIES["api_key_creation"].fail_open is False
    # ingestion fails open — availability of core log collection outranks
    # strict limiting during a Redis outage
    assert RATE_LIMIT_POLICIES["ingestion"].fail_open is True


# ── enforce_rate_limit: boundary, Retry-After, fail-open/closed ────


def _test_policy(name: str, requests: int, fail_open: bool) -> RateLimitPolicy:
    return RateLimitPolicy(name=name, requests=requests, window_seconds=60, fail_open=fail_open)


@pytest.mark.asyncio
async def test_requests_within_limit_do_not_raise() -> None:
    policy = _test_policy(f"unit-{uuid.uuid4().hex[:8]}", requests=3, fail_open=False)
    identity = "client-a"
    for _ in range(3):
        await enforce_rate_limit(policy, identity)  # no raise


@pytest.mark.asyncio
async def test_exceeding_limit_raises_429_with_retry_after() -> None:
    policy = _test_policy(f"unit-{uuid.uuid4().hex[:8]}", requests=2, fail_open=False)
    identity = "client-b"
    await enforce_rate_limit(policy, identity)
    await enforce_rate_limit(policy, identity)

    with pytest.raises(HTTPException) as exc_info:
        await enforce_rate_limit(policy, identity)

    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers
    assert int(exc_info.value.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_limit_is_isolated_per_identity() -> None:
    policy = _test_policy(f"unit-{uuid.uuid4().hex[:8]}", requests=1, fail_open=False)
    await enforce_rate_limit(policy, "identity-1")
    await enforce_rate_limit(policy, "identity-2")  # different identity, own budget — no raise

    with pytest.raises(HTTPException):
        await enforce_rate_limit(policy, "identity-1")


@pytest.mark.asyncio
async def test_limit_is_isolated_per_policy_name() -> None:
    identity = "shared-identity"
    policy_a = _test_policy(f"unit-a-{uuid.uuid4().hex[:8]}", requests=1, fail_open=False)
    policy_b = _test_policy(f"unit-b-{uuid.uuid4().hex[:8]}", requests=1, fail_open=False)
    await enforce_rate_limit(policy_a, identity)
    await enforce_rate_limit(policy_b, identity)  # different policy, own budget — no raise


@pytest.mark.asyncio
async def test_redis_failure_fails_closed_when_configured() -> None:
    policy = _test_policy(f"unit-{uuid.uuid4().hex[:8]}", requests=100, fail_open=False)
    with patch("app.core.rate_limit.get_redis", new=AsyncMock(side_effect=RedisError("down"))):
        with pytest.raises(HTTPException) as exc_info:
            await enforce_rate_limit(policy, "any-identity")
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_failure_fails_open_when_configured() -> None:
    policy = _test_policy(f"unit-{uuid.uuid4().hex[:8]}", requests=100, fail_open=True)
    with patch("app.core.rate_limit.get_redis", new=AsyncMock(side_effect=RedisError("down"))):
        await enforce_rate_limit(policy, "any-identity")  # no raise


# ── security headers ────────────────────────────────────────────


def _client():
    from fastapi.testclient import TestClient
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


def test_health_response_includes_baseline_security_headers() -> None:
    response = _client().get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")


def test_hsts_absent_by_default_and_present_in_production() -> None:
    from app.core.config import settings

    response = _client().get("/health")
    assert "Strict-Transport-Security" not in response.headers

    original = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        response = _client().get("/health")
        assert "Strict-Transport-Security" in response.headers
    finally:
        settings.ENVIRONMENT = original
