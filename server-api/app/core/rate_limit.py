# server-api/app/core/rate_limit.py
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.exceptions import RedisError

from app.core.deps import get_agent, get_current_user
from app.core.redis_client import get_redis

_KEY_PREFIX = "ratelimit"


@dataclass(frozen=True)
class RateLimitPolicy:
    name: str
    requests: int
    window_seconds: int
    fail_open: bool  # behavior when Redis itself is unreachable, NOT when the limit is exceeded


# Fail-open/fail-closed table (explicit, not inferred): authentication and
# API-key creation fail closed — if we cannot verify the caller is within
# limit, we must not let an unlimited flood of auth/credential-issuance
# attempts through. Repository import and AI chat also fail closed: both
# trigger real external cost/risk (outbound fetches, paid LLM calls) that an
# attacker could otherwise use a Redis outage to amplify. Ingestion and SOAR
# approval fail open: blocking log ingestion or incident-response approvals
# during a Redis blip is a worse outcome than temporarily unmetered access to
# an already-authenticated, already-permission-checked action.
RATE_LIMIT_POLICIES: dict[str, RateLimitPolicy] = {
    "login": RateLimitPolicy("login", requests=5, window_seconds=60, fail_open=False),
    "mfa": RateLimitPolicy("mfa", requests=5, window_seconds=60, fail_open=False),
    "api_key_creation": RateLimitPolicy("api_key_creation", requests=10, window_seconds=60, fail_open=False),
    "repository_import": RateLimitPolicy("repository_import", requests=5, window_seconds=60, fail_open=False),
    "ai_chat": RateLimitPolicy("ai_chat", requests=20, window_seconds=60, fail_open=False),
    "ingestion": RateLimitPolicy("ingestion", requests=1200, window_seconds=60, fail_open=True),
    "soar_approval": RateLimitPolicy("soar_approval", requests=20, window_seconds=60, fail_open=True),
}


async def enforce_rate_limit(policy: RateLimitPolicy, identity: str) -> None:
    """Fixed-window limiter. Raises 429 with Retry-After when the caller has
    exceeded `policy.requests` within the current `policy.window_seconds`
    window. On a Redis failure, follows `policy.fail_open` rather than always
    failing one way, since the safe default differs by route (see the table
    above).
    """
    window_bucket = int(time.time()) // policy.window_seconds
    key = f"{_KEY_PREFIX}:{policy.name}:{identity}:{window_bucket}"

    try:
        redis = await get_redis()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, policy.window_seconds)
    except RedisError:
        if policy.fail_open:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting is temporarily unavailable; request rejected for safety",
        )

    if count > policy.requests:
        window_end = (window_bucket + 1) * policy.window_seconds
        retry_after = max(1, math.ceil(window_end - time.time()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {policy.name}: {policy.requests} requests per {policy.window_seconds}s",
            headers={"Retry-After": str(retry_after)},
        )


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_by_ip(policy_name: str):
    """For unauthenticated routes: key on the caller's client IP."""
    policy = RATE_LIMIT_POLICIES[policy_name]

    async def dependency(request: Request) -> None:
        await enforce_rate_limit(policy, _client_ip(request))

    return dependency


def rate_limit_by_user_group(policy_name: str):
    """For JWT/API-key-authenticated routes: key on the caller's tenant
    (group_id), not the individual user — matching the plan's "tenant or
    unauthenticated client identity" identity model."""
    policy = RATE_LIMIT_POLICIES[policy_name]

    async def dependency(current_user: Annotated[object, Depends(get_current_user)]) -> None:
        group_id = getattr(current_user, "group_id", None) or "default"
        await enforce_rate_limit(policy, group_id)

    return dependency


def rate_limit_by_agent_group(policy_name: str):
    """For agent-token-authenticated routes (ingestion): key on the agent's
    tenant (group_id)."""
    policy = RATE_LIMIT_POLICIES[policy_name]

    async def dependency(agent: Annotated[object, Depends(get_agent)]) -> None:
        group_id = getattr(agent, "group_id", None) or "default"
        await enforce_rate_limit(policy, group_id)

    return dependency
