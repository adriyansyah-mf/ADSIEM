"""Syslog sources API + the receiver reading what it stores (needs TEST_DATABASE_URL)."""
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

ADMIN_PERMS = ("agents:read", "agents:manage")


def evidence_user(role, group, perms):
    return SimpleNamespace(id=uuid4(), group_id=group, username=role,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


class _HashRedis:
    def __init__(self):
        self.kv = {}

    async def hmget(self, key, fields):
        return [self.kv.get(key, {}).get(f) for f in fields]

    async def hset(self, key, mapping):
        self.kv.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        pass

    async def hgetall(self, key):
        return dict(self.kv.get(key) or {})

    async def hkeys(self, key):
        return list(self.kv.get(key) or {})

    async def hdel(self, key, *fields):
        for f in fields:
            self.kv.get(key, {}).pop(f, None)


@pytest.fixture
async def syslog_env(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs TEST_DATABASE_URL (disposable PostgreSQL)")
    import httpx
    from fastapi import FastAPI
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.routes import syslog_sources
    from app.core.database import get_db
    from app.core.deps import get_current_user
    from app.core.redis_client import get_redis
    from app.models.models import SyslogSource

    schema = "syslog_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as db:
        await db.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.run_sync(lambda c: SyslogSource.__table__.create(c))
        env = SimpleNamespace(sessions=sessions, redis=_HashRedis(), audits=[],
                              user=evidence_user("analyst", "blue", ADMIN_PERMS))

        async def database():
            async with sessions() as db:
                yield db

        async def redis():
            return env.redis

        async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None):
            env.audits.append((action, resource_id, detail))

        app = FastAPI()
        app.include_router(syslog_sources.router)
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_redis] = redis
        app.dependency_overrides[get_current_user] = lambda: env.user
        monkeypatch.setattr(syslog_sources, "audit_log", audit)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def _create(env, **body):
    body = {"name": "fw-hq", "cidr": "10.0.5.1", "log_type": "fortigate_traffic", **body}
    return await env.client.post("/api/syslog-sources", json=body)


async def test_create_normalizes_and_scopes_to_the_callers_group(syslog_env):
    r = await _create(syslog_env, group_id="red")  # not a superadmin: group_id is ignored
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["cidr"] == "10.0.5.1/32" and row["group_id"] == "blue" and row["message_count"] == 0
    assert syslog_env.audits[0][0] == "syslog_source.create"


async def test_validation(syslog_env):
    assert (await _create(syslog_env, cidr="not-an-ip")).status_code == 422
    assert (await _create(syslog_env, log_type="Bad Type")).status_code == 422
    assert (await _create(syslog_env, cidr="10.0.0.0/8")).status_code == 403  # too broad for a group admin


async def test_duplicate_cidr_is_a_conflict(syslog_env):
    assert (await _create(syslog_env, cidr="10.0.5.0/24")).status_code == 201
    assert (await _create(syslog_env, cidr="10.0.5.7/24")).status_code == 409  # same network once normalized


async def test_other_groups_cannot_see_or_change_a_source(syslog_env):
    source_id = (await _create(syslog_env)).json()["id"]
    syslog_env.user = evidence_user("analyst", "red", ADMIN_PERMS)
    assert (await syslog_env.client.get("/api/syslog-sources")).json() == []
    assert (await syslog_env.client.put(f"/api/syslog-sources/{source_id}", json={"enabled": False})).status_code == 404
    assert (await syslog_env.client.delete(f"/api/syslog-sources/{source_id}")).status_code == 404


async def test_update_and_delete(syslog_env):
    source_id = (await _create(syslog_env)).json()["id"]
    r = await syslog_env.client.put(f"/api/syslog-sources/{source_id}", json={"log_type": "cef", "enabled": False})
    assert r.status_code == 200 and r.json()["log_type"] == "cef" and r.json()["enabled"] is False
    assert (await syslog_env.client.delete(f"/api/syslog-sources/{source_id}")).status_code == 204
    assert (await syslog_env.client.get("/api/syslog-sources")).json() == []


async def test_read_needs_no_manage_permission_but_writes_do(syslog_env):
    syslog_env.user = evidence_user("viewer", "blue", ("agents:read",))
    assert (await syslog_env.client.get("/api/syslog-sources")).status_code == 200
    assert (await _create(syslog_env)).status_code == 403


async def test_unknown_senders_are_superadmin_only_and_cleared_on_register(syslog_env):
    syslog_env.redis.kv["siem:syslog:unknown"] = {
        "10.0.5.1": json.dumps({"count": 4, "last_seen": "2026-05-01T10:00:00+00:00", "sample": "date=...", "proto": "udp"}),
        "10.0.6.1": json.dumps({"count": 1, "last_seen": "2026-05-01T09:00:00+00:00", "sample": "x", "proto": "tcp"}),
    }
    assert (await syslog_env.client.get("/api/syslog-sources/unknown")).status_code == 403
    syslog_env.user = evidence_user("superadmin", "default", ())
    rows = (await syslog_env.client.get("/api/syslog-sources/unknown")).json()
    assert [r["ip"] for r in rows] == ["10.0.5.1", "10.0.6.1"] and rows[0]["count"] == 4
    assert (await _create(syslog_env, group_id="red")).json()["group_id"] == "red"  # superadmin picks the group
    assert set(syslog_env.redis.kv["siem:syslog:unknown"]) == {"10.0.6.1"}


async def test_receiver_loads_enabled_sources_and_writes_stats(syslog_env):
    from worker import syslog_receiver as sr

    fw = (await _create(syslog_env)).json()
    await _create(syslog_env, name="lan", cidr="10.0.0.0/16", log_type="cef")
    await _create(syslog_env, name="off", cidr="10.0.9.9", enabled=False)
    table = await sr.load_table(syslog_env.sessions)
    assert len(table) == 2
    assert table.lookup("10.0.5.1").name == "fw-hq"      # most specific wins
    assert table.lookup("10.0.7.7").log_type == "cef"
    assert table.lookup("10.0.9.9").name == "lan"         # disabled /32 falls back to the /16

    rx = sr.Receiver(_HashRedis(), table)
    for _ in range(3):
        rx.submit("10.0.5.1", b"<13>date=x devname=y", "udp")
    await rx.write_stats(syslog_env.sessions)
    rows = {r["name"]: r for r in (await syslog_env.client.get("/api/syslog-sources")).json()}
    assert rows["fw-hq"]["message_count"] == 3 and rows["fw-hq"]["last_seen_at"]
    assert rows["fw-hq"]["id"] == fw["id"]
