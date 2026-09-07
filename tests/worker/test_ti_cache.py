from __future__ import annotations

import pytest

from worker.ti.cache import PROVIDER_TTL_SECONDS, cache_key, get_or_fetch


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)
        self._now = 0.0

    def advance(self, seconds: float) -> None:
        self._now += seconds

    async def get(self, key: str) -> str | None:
        entry = self.store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at <= self._now:
            del self.store[key]
            return None
        return value

    async def set(self, key: str, value: str, ex: int) -> None:
        self.store[key] = (value, self._now + ex)


def test_cache_key_is_scoped_per_tenant_provider_type_and_indicator() -> None:
    a = cache_key("blue", "virustotal", "ip", "1.2.3.4")
    b = cache_key("red", "virustotal", "ip", "1.2.3.4")
    c = cache_key("blue", "abuseipdb", "ip", "1.2.3.4")
    d = cache_key("blue", "virustotal", "domain", "1.2.3.4")
    assert len({a, b, c, d}) == 4  # all distinct


@pytest.mark.asyncio
async def test_miss_calls_fetch_and_caches_result() -> None:
    redis = _FakeRedis()
    calls = 0

    async def fetch():
        nonlocal calls
        calls += 1
        return {"malicious": True}

    result = await get_or_fetch(
        redis, tenant="blue", provider="virustotal", lookup_type="ip", indicator="1.2.3.4", fetch=fetch, now=redis._now,
    )
    assert calls == 1
    assert result["malicious"] is True
    assert result["_stale"] is False
    assert result["_cached"] is False


@pytest.mark.asyncio
async def test_fresh_hit_does_not_call_fetch() -> None:
    redis = _FakeRedis()
    calls = 0

    async def fetch():
        nonlocal calls
        calls += 1
        return {"malicious": True}

    await get_or_fetch(redis, tenant="blue", provider="virustotal", lookup_type="ip", indicator="1.2.3.4", fetch=fetch)
    result = await get_or_fetch(redis, tenant="blue", provider="virustotal", lookup_type="ip", indicator="1.2.3.4", fetch=fetch)

    assert calls == 1  # second call served entirely from cache
    assert result["_cached"] is True
    assert result["_stale"] is False


@pytest.mark.asyncio
async def test_expired_entry_refetches_when_provider_succeeds() -> None:
    redis = _FakeRedis()
    calls = 0

    async def fetch():
        nonlocal calls
        calls += 1
        return {"version": calls}

    await get_or_fetch(
        redis, tenant="blue", provider="abuseipdb", lookup_type="ip", indicator="9.9.9.9",
        fetch=fetch, ttl_seconds=10, now=redis._now,
    )
    redis.advance(11)  # past TTL
    result = await get_or_fetch(
        redis, tenant="blue", provider="abuseipdb", lookup_type="ip", indicator="9.9.9.9",
        fetch=fetch, ttl_seconds=10, now=redis._now,
    )

    assert calls == 2
    assert result["version"] == 2
    assert result["_stale"] is False
    assert result["_cached"] is False


@pytest.mark.asyncio
async def test_expired_entry_falls_back_to_stale_when_provider_fails() -> None:
    redis = _FakeRedis()

    async def fetch_ok():
        return {"malicious": True}

    async def fetch_fail():
        raise RuntimeError("provider unavailable")

    await get_or_fetch(
        redis, tenant="blue", provider="otx", lookup_type="domain", indicator="evil.test",
        fetch=fetch_ok, ttl_seconds=10, now=redis._now,
    )
    redis.advance(11)
    result = await get_or_fetch(
        redis, tenant="blue", provider="otx", lookup_type="domain", indicator="evil.test",
        fetch=fetch_fail, ttl_seconds=10, now=redis._now,
    )

    assert result["malicious"] is True  # stale data still returned
    assert result["_stale"] is True
    assert result["_cached"] is True
    assert "provider unavailable" in result["_error"]


@pytest.mark.asyncio
async def test_no_cache_and_fetch_failure_propagates() -> None:
    redis = _FakeRedis()

    async def fetch_fail():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await get_or_fetch(
            redis, tenant="blue", provider="shodan", lookup_type="ip", indicator="1.1.1.1",
            fetch=fetch_fail, now=redis._now,
        )


@pytest.mark.asyncio
async def test_stale_retention_outlives_fresh_ttl() -> None:
    """A stale copy must still be servable well after the fresh TTL elapses
    (retained at STALE_RETENTION_MULTIPLIER x TTL), not disappear the instant
    it goes stale."""
    redis = _FakeRedis()

    async def fetch_ok():
        return {"data": "x"}

    async def fetch_fail():
        raise RuntimeError("down")

    await get_or_fetch(
        redis, tenant="blue", provider="urlhaus", lookup_type="url", indicator="http://x",
        fetch=fetch_ok, ttl_seconds=10, now=redis._now,
    )
    redis.advance(35)  # well past the 10s TTL, but under 4x (40s) retention
    result = await get_or_fetch(
        redis, tenant="blue", provider="urlhaus", lookup_type="url", indicator="http://x",
        fetch=fetch_fail, ttl_seconds=10, now=redis._now,
    )
    assert result["_stale"] is True
    assert result["data"] == "x"


def test_every_wired_provider_has_an_explicit_ttl() -> None:
    for provider in ("virustotal", "abuseipdb", "otx", "greynoise", "shodan", "urlhaus", "whois", "geoip"):
        assert provider in PROVIDER_TTL_SECONDS
        assert PROVIDER_TTL_SECONDS[provider] > 0
