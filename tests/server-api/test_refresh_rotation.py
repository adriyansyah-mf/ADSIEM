"""Refresh tokens rotate on every refresh, a replaced one is refused after a
short grace, logout revokes it, and a Redis outage doesn't log users out."""
import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import auth
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.redis_client import get_redis
from app.core.security import create_refresh_token, hash_password


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)


class FakeRedis:
    def __init__(self):
        self.kv, self.ttl, self.down = {}, {}, False

    def _check(self):
        if self.down:
            raise ConnectionError("redis down")

    async def set(self, key, value, ex=None):
        self._check()
        self.kv[key], self.ttl[key] = value, ex

    async def get(self, key):
        self._check()
        return self.kv.get(key)

    async def delete(self, key):
        self._check()
        self.kv.pop(key, None)


class FakeDB:
    def __init__(self, user):
        self.user = user

    async def execute(self, *a, **kw):
        user = self.user
        return SimpleNamespace(scalar_one_or_none=lambda: user)


@pytest.fixture
def api(monkeypatch):
    user = SimpleNamespace(id=uuid4(), username="ana", password_hash=hash_password("pw"), mfa_enabled=False,
                           mfa_secret=None, is_active=True, role=SimpleNamespace(name="analyst"))
    redis = FakeRedis()
    app = FastAPI()
    app.state.limiter = limiter
    limiter.reset()
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(auth.router)

    async def db():
        yield FakeDB(user)

    async def r():
        return redis

    audits = []

    async def record_audit(db, actor_id, action, *a, **kw):
        audits.append(action)

    app.dependency_overrides[get_db] = db
    app.dependency_overrides[get_redis] = r
    monkeypatch.setattr(auth, "audit_log", record_audit)
    app.state.audits = audits
    return app, redis, user


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _login(c):
    resp = await c.post("/api/auth/login", json={"username": "ana", "password": "pw"})
    assert resp.status_code == 200, resp.text
    return resp.cookies["refresh_token"]


async def test_each_refresh_rotates_the_token(api):
    app, redis, _ = api
    async with _client(app) as c:
        first = await _login(c)
        resp = await c.post("/api/auth/refresh")
        assert resp.status_code == 200 and resp.json()["access_token"]
        second = resp.cookies["refresh_token"]
        assert second != first
        assert sorted(redis.kv.values()) == sorted(["rotated", str(api[2].id)])
        assert (await c.post("/api/auth/refresh")).status_code == 200   # the new one works


async def test_a_replaced_token_works_within_the_grace_then_is_refused(api):
    app, redis, _ = api
    async with _client(app) as c:
        first = await _login(c)
        await c.post("/api/auth/refresh")
        # a concurrent tab still sending the old cookie, inside the grace: accepted, not rotated again
        c.cookies.clear()
        c.cookies.set("refresh_token", first)
        ok = await c.post("/api/auth/refresh")
        assert ok.status_code == 200 and "refresh_token" not in ok.cookies
        # grace over: the old token is refused
        for key, value in list(redis.kv.items()):
            if value == "rotated":
                del redis.kv[key]
        assert (await c.post("/api/auth/refresh")).status_code == 401


async def test_logout_revokes_the_token_and_clears_the_cookie(api):
    app, redis, _ = api
    async with _client(app) as c:
        token = await _login(c)
        out = await c.post("/api/auth/logout")
        assert out.status_code == 204
        assert 'refresh_token=""' in out.headers["set-cookie"] or "Max-Age=0" in out.headers["set-cookie"]
        assert redis.kv == {}
        c.cookies.clear()
        c.cookies.set("refresh_token", token)       # a copy of the cookie taken before logout
        assert (await c.post("/api/auth/refresh")).status_code == 401


async def test_logout_without_a_session_still_succeeds(api):
    app, _, _ = api
    async with _client(app) as c:
        assert (await c.post("/api/auth/logout")).status_code == 204


async def test_a_redis_outage_does_not_log_users_out(api):
    app, redis, _ = api
    async with _client(app) as c:
        await _login(c)
        redis.down = True
        resp = await c.post("/api/auth/refresh")
        assert resp.status_code == 200 and resp.json()["access_token"]


async def test_tokens_from_before_rotation_are_accepted_once_and_replaced(api):
    app, redis, user = api
    legacy = create_refresh_token(str(user.id))     # no jti
    async with _client(app) as c:
        c.cookies.set("refresh_token", legacy)
        resp = await c.post("/api/auth/refresh")
        assert resp.status_code == 200 and resp.cookies.get("refresh_token") not in (None, legacy)
        assert list(redis.kv.values()) == [str(user.id)]


async def test_a_refused_refresh_is_audited(api):
    # audited inline: a background task would never run on a failed request
    app, redis, _ = api
    async with _client(app) as c:
        await _login(c)
        redis.kv.clear()                                   # revoked
        assert (await c.post("/api/auth/refresh")).status_code == 401
    assert "refresh_token_rejected" in app.state.audits


async def test_login_during_a_redis_outage_does_not_log_the_user_out_later(api):
    from app.core.security import decode_token

    app, redis, _ = api
    async with _client(app) as c:
        redis.down = True
        token = await _login(c)
        assert "jti" not in decode_token(token)            # Redis couldn't store one
        redis.down = False
        resp = await c.post("/api/auth/refresh")           # accepted once, replaced by a tracked token
        assert resp.status_code == 200 and "jti" in decode_token(resp.cookies["refresh_token"])
