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


@pytest.fixture
async def case_env(monkeypatch):
    import httpx
    from fastapi import FastAPI
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.api.routes.cases import router
    from app.api.routes.soar import router as soar_router
    from app.core.database import Base, get_db
    from app.core import database as api_database
    from app.core.deps import get_current_user
    from app.models.models import Agent, AgentTask, Alert, Case, CaseAlert, Role, User

    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "case_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tables = {model.__table__ for model in (Agent, AgentTask, Alert, Case, CaseAlert, Role, User)}
    tables.add(Base.metadata.tables["case_notes"])
    tables.add(Base.metadata.tables["alert_notes"])
    tables.update(Base.metadata.tables[name] for name in (
        "soar_case_events", "soar_playbooks", "soar_actions", "soar_playbook_runs", "soar_playbook_run_steps",
        "platform_settings", "audit_logs",
    ))
    monkeypatch.setattr(api_database, "AsyncSessionLocal", sessions)
    while True:
        dependencies = {fk.column.table for table in tables for fk in table.foreign_keys}
        if dependencies <= tables:
            break
        tables |= dependencies
    async with engine.begin() as connection:
        await connection.run_sync(lambda connection: Base.metadata.create_all(connection, tables=list(tables)))
    async with sessions() as db:
        role = Role(name="admin")
        db.add(role)
        await db.flush()
        user = User(username="test", email="test@example.com", password_hash="test", role_id=role.id, group_id="blue")
        agents = [Agent(name=f"host{i}", hostname=f"host{i}", group_id=group, token_hash=uuid4().hex, approved=True, status="online")
                  for i, group in enumerate(("blue", "blue", "red"))]
        db.add_all([user, *agents])
        await db.flush()
        alerts = [Alert(title="Brute force", severity="high", group_id=a.group_id, agent_id=a.id,
                        hostname=a.hostname, source_ip=f"8.8.8.{i + 1}") for i, a in enumerate(agents)]
        db.add_all(alerts)
        await db.flush()
        case = Case(title="Distributed brute force", severity="high", status="open", group_id="blue", alert_id=alerts[0].id,
                    ioc_data={"affected_hosts": ["host0", "host1"], "ioc_keys": ["ip:8.8.8.2"]})
        db.add(case)
        await db.flush()
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[1].id, status="linked", method="ai",
                         reason="Same account and service", confidence=0.96, indicators=["ip:8.8.8.2"], accounts=["admin"]))
        await db.commit()
        env = SimpleNamespace(sessions=sessions, case=case, alerts=alerts, agents=agents,
                              user=SimpleNamespace(id=user.id, username="test", group_id="blue",
                                  role=SimpleNamespace(name="admin", permissions=[SimpleNamespace(name=n)
                                      for n in ("cases:manage", "agents:manage")])))
    app = FastAPI()
    app.include_router(router)
    app.include_router(soar_router)

    async def database():
        async with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: env.user
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()
