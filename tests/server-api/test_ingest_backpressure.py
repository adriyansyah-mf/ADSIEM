"""Legacy agent ingest pushes back (429 + Retry-After) when the workers are far
behind, but only to agents that said they retry it."""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import ingest as ingest_routes
from app.core.config import settings
from app.core.deps import get_agent
from app.core.redis_client import get_redis
from app.services import ingest as ingest_service


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    # pytest-asyncio 0.24 (CI) runs the test on the *current* loop
    asyncio.set_event_loop(event_loop)


class FakeRedis:
    def __init__(self, length):
        self.length, self.items = length, []

    async def xlen(self, key):
        return self.length

    async def xadd(self, key, data, **kw):
        self.items.append(data)

    async def set(self, *a, **kw):
        return True


@pytest.fixture
def api(monkeypatch):
    redis = FakeRedis(0)
    agent = SimpleNamespace(id=uuid4(), group_id="blue", hostname="h", approved=True)
    app = FastAPI()
    app.include_router(ingest_routes.router)

    async def fake_redis():
        return redis

    app.dependency_overrides[get_agent] = lambda: agent
    app.dependency_overrides[get_redis] = fake_redis
    monkeypatch.setitem(ingest_service._backlog, "at", 0.0)  # no cached length between tests
    return app, redis


LINE = {"agent_id": str(uuid4()), "hostname": "h", "log_type": "linux_auth", "raw_message": "hello",
        "received_at": datetime.now(timezone.utc).isoformat()}


async def _post(app, path, body, header):
    headers = {ingest_service.BACKPRESSURE_HEADER: "1"} if header else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.post(path, json=body, headers=headers)


@pytest.mark.parametrize("path,body", [("/api/ingest/log", LINE), ("/api/ingest/logs", {"entries": [LINE, LINE]})])
async def test_backed_up_queue_returns_429_to_agents_that_retry_it(api, path, body):
    app, redis = api
    redis.length = settings.INGEST_BACKLOG_LIMIT
    resp = await _post(app, path, body, header=True)
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == str(settings.INGEST_RETRY_AFTER_SECONDS)
    assert redis.items == []                                  # nothing queued


@pytest.mark.parametrize("path,body", [("/api/ingest/log", LINE), ("/api/ingest/logs", {"entries": [LINE]})])
async def test_older_agents_are_never_refused(api, path, body):
    # agents without the header treat a 4xx as "sent" and would drop the lines
    app, redis = api
    redis.length = settings.INGEST_BACKLOG_LIMIT * 2
    resp = await _post(app, path, body, header=False)
    assert resp.status_code == 202 and len(redis.items) == len(body.get("entries", [body]))


async def test_below_the_limit_lines_are_queued(api):
    app, redis = api
    redis.length = settings.INGEST_BACKLOG_LIMIT - 1
    resp = await _post(app, "/api/ingest/log", LINE, header=True)
    assert resp.status_code == 202 and len(redis.items) == 1


async def test_backlog_length_is_cached_and_redis_errors_never_refuse(monkeypatch):
    calls = []

    class Counting:
        async def xlen(self, key):
            calls.append(key)
            return 5

    class Broken:
        async def xlen(self, key):
            raise ConnectionError("down")

    monkeypatch.setitem(ingest_service._backlog, "at", 0.0)
    r = Counting()
    assert await ingest_service.stream_backlog(r) == 5
    assert await ingest_service.stream_backlog(r) == 5
    assert len(calls) == 1
    monkeypatch.setitem(ingest_service._backlog, "at", 0.0)
    assert await ingest_service.stream_backlog(Broken()) == 0
