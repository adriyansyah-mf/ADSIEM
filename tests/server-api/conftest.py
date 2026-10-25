import pytest
import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


class _Redis:
    """Enough of Redis for the heartbeat route (session continuity, log queue)."""

    def __init__(self):
        self.kv, self.items = {}, []

    async def xadd(self, *a, **kw):
        self.items.append(a)

    async def hgetall(self, key):
        return dict(self.kv.get(key) or {})

    async def hset(self, key, mapping):
        self.kv.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        pass

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True


def evidence_user(role="analyst", group="blue", perms=("agents:read",)):
    return SimpleNamespace(id=uuid4(), group_id=group, username=role,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture
async def evidence_api(monkeypatch):
    """Ingest + evidence routes over a disposable schema of TEST_DATABASE_URL.

    Agents: blue (token "blue-token") and red (token "red-token"). Set
    env.user to change who calls the operator API; env.audits records audit
    calls instead of writing them."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs TEST_DATABASE_URL (disposable PostgreSQL)")
    import httpx
    from fastapi import FastAPI
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.routes import evidence, ingest
    from app.core.database import Base, get_db
    from app.core.deps import get_current_user
    from app.core.redis_client import get_redis
    from app.core.security import hash_token
    from app.models import models

    namespace = "evidence_api_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as db:
        await db.execute(text("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"))
        await db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{namespace},public"}},
                                 execution_options={"schema_translate_map": {None: namespace}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.run_sync(Base.metadata.create_all)
        agents = {}
        async with sessions() as db:
            for group in ("blue", "red"):
                a = models.Agent(name=group, hostname=f"{group}-host", group_id=group,
                                 token_hash=hash_token(f"{group}-token"), approved=True)
                db.add(a)
                await db.flush()
                agents[group] = a.id
            await db.commit()

        env = SimpleNamespace(sessions=sessions, agents=agents, user=evidence_user(), audits=[], redis=_Redis(),
                              make_user=evidence_user)

        async def database():
            async with sessions() as db:
                yield db

        async def redis():
            return env.redis

        async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None):
            env.audits.append((actor_id, action, resource_id, detail))

        app = FastAPI()
        app.include_router(ingest.router)
        app.include_router(evidence.router)
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_redis] = redis
        app.dependency_overrides[get_current_user] = lambda: env.user
        monkeypatch.setattr(evidence, "audit_log", audit)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()
