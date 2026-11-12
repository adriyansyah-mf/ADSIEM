"""Login rate limit keys on nginx's X-Real-IP (not client-controlled
X-Forwarded-For), users can't get an empty tenant group, and /health reports
Elasticsearch."""
import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.datastructures import Headers

from app.core import deps
from app.core.limiter import _real_ip
from app.schemas.schemas import UserCreate, UserUpdate


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    # pytest-asyncio 0.24 (CI) runs the test on the *current* loop; modules run
    # earlier in the session (asyncio.run, private loops) can leave none.
    asyncio.set_event_loop(event_loop)


def _request(headers: dict, client=("10.9.0.5", 1234)) -> Request:
    scope = {"type": "http", "headers": Headers(headers).raw, "client": client, "method": "POST", "path": "/"}
    return Request(scope)


# ── rate-limit key ────────────────────────────────────────────────────────────

def test_spoofed_forwarded_for_is_ignored():
    assert _real_ip(_request({"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "203.0.113.7"})) == "203.0.113.7"
    assert _real_ip(_request({"X-Forwarded-For": "1.2.3.4"})) == "10.9.0.5"


def test_falls_back_to_the_connection_address():
    assert _real_ip(_request({})) == "10.9.0.5"
    assert _real_ip(_request({}, client=None)) == "127.0.0.1"


async def test_rotating_forwarded_for_no_longer_escapes_the_login_limit():
    limiter = Limiter(key_func=_real_ip)
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.post("/login")
    @limiter.limit("3/minute")
    async def login(request: Request):
        return {"ok": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        codes = [(await c.post("/login", headers={"X-Real-IP": "198.51.100.9", "X-Forwarded-For": f"10.0.0.{i}"}))
                 .status_code for i in range(5)]
        other = await c.post("/login", headers={"X-Real-IP": "198.51.100.10"})
    assert codes == [200, 200, 200, 429, 429]
    assert other.status_code == 200  # a different client keeps its own bucket


# ── tenant group ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("group", ["", "   "])
def test_user_schemas_refuse_an_empty_group(group):
    with pytest.raises(ValidationError):
        UserCreate(username="u", email="u@example.com", password="p", role_id=1, group_id=group)
    with pytest.raises(ValidationError):
        UserUpdate(group_id=group)


def test_user_schemas_keep_a_real_group_and_allow_omitting_it():
    assert UserCreate(username="u", email="u@example.com", password="p", role_id=1, group_id=" blue ").group_id == "blue"
    assert UserCreate(username="u", email="u@example.com", password="p", role_id=1).group_id == "default"
    assert UserUpdate().group_id is None


def _user(role: str, group):
    return SimpleNamespace(id=uuid4(), group_id=group, role=SimpleNamespace(name=role, permissions=[]))


def test_scoped_group_refuses_a_groupless_non_superadmin():
    for group in ("", "  ", None):
        with pytest.raises(HTTPException) as exc:
            deps.get_scoped_group(_user("analyst", group))
        assert exc.value.status_code == 403
    assert deps.get_scoped_group(_user("analyst", "blue")) == "blue"
    assert deps.get_scoped_group(_user("superadmin", "")) is None


# ── /health ───────────────────────────────────────────────────────────────────

async def test_health_reports_elasticsearch(monkeypatch):
    from app.api.routes import system

    class _Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, *a):
            return None

    class _Redis:
        async def ping(self):
            return True

    async def redis():
        return _Redis()

    async def es_down():
        return False

    async def es_up():
        return True

    monkeypatch.setattr(system, "engine", SimpleNamespace(connect=lambda: _Conn()))
    monkeypatch.setattr(system, "get_redis", redis)
    monkeypatch.setattr(system.es_client, "ping", es_down)
    body = await system.health()
    assert body["elasticsearch"] == "error" and body["status"] == "degraded"
    monkeypatch.setattr(system.es_client, "ping", es_up)
    body = await system.health()
    assert body["elasticsearch"] == "ok" and body["status"] == "ok"
