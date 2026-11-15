"""Audit log (services/audit.py, services/audit_chain.py, routes/audit_logs.py,
routes/auth.py): every row is chained by the database, cannot be changed or
deleted, records the caller's address and user agent, and the verifier finds
any edit made by someone who switched the guards off."""
import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.api.routes import audit_logs, auth
from app.core import request_context
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.limiter import limiter
from app.core.redis_client import get_redis
from app.core.request_context import RequestContextMiddleware
from app.core.security import hash_password
from app.models.models import Role, User
from app.services import audit_chain
from app.services.audit import audit_log


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


class _Redis:
    def __init__(self):
        self.kv = {}

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def get(self, key):
        return self.kv.get(key)

    async def delete(self, key):
        self.kv.pop(key, None)


def _person(role="superadmin", perms=()):
    return SimpleNamespace(id=uuid4(), username=f"{role}-user", group_id="blue",
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async with evidence_api.sessions() as db:
        await audit_chain.ensure(await db.connection())
        await db.commit()

    async def database():
        async with evidence_api.sessions() as db:
            yield db

    redis = _Redis()
    app = FastAPI()
    app.state.limiter = limiter
    limiter.enabled = False  # five logins a minute is the production limit; these tests log in more
    app.include_router(auth.router)
    app.include_router(audit_logs.router)
    app.add_middleware(RequestContextMiddleware)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_redis] = lambda: redis
    evidence_api.user = _person()
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user

    async def no_checkpoint():
        return evidence_api.checkpoint
    evidence_api.checkpoint = None
    monkeypatch.setattr(audit_logs, "latest_checkpoint", no_checkpoint)
    headers = {"X-Real-IP": "203.0.113.7", "User-Agent": "pytest-browser/1.0"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                                 headers=headers) as client:
        evidence_api.api = client
        yield evidence_api
    limiter.enabled = True


async def _rows(env):
    async with env.sessions() as db:
        return (await db.execute(text(
            "SELECT seq, prev_hash, hash, action, outcome, ip_address, user_agent, request, actor_name, detail "
            "FROM audit_logs ORDER BY seq"))).mappings().all()


async def test_rows_are_chained_and_carry_the_callers_address(env):
    token = request_context._current.set({"ip": "198.51.100.4", "user_agent": "Firefox", "request": "POST /api/x"})
    try:
        for i in range(3):
            await audit_log(None, None, f"thing_{i}", "test", str(i), {"n": i}, actor_name="ana")
    finally:
        request_context._current.reset(token)
    rows = await _rows(env)
    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert rows[0]["prev_hash"] == audit_chain.GENESIS
    assert rows[1]["prev_hash"] == rows[0]["hash"] and rows[2]["prev_hash"] == rows[1]["hash"]
    assert rows[0]["ip_address"] == "198.51.100.4" and rows[0]["user_agent"] == "Firefox"
    assert rows[0]["request"] == "POST /api/x" and rows[0]["outcome"] == "success" and rows[0]["actor_name"] == "ana"
    async with env.sessions() as db:
        assert (await audit_chain.verify(db))["ok"] is True


async def test_rows_cannot_be_changed_deleted_or_truncated(env):
    await audit_log(None, None, "login_success", "user", "x")
    for sql in ("UPDATE audit_logs SET action = 'nothing'", "DELETE FROM audit_logs", "TRUNCATE audit_logs"):
        async with env.sessions() as db:
            with pytest.raises(DBAPIError, match="append-only"):
                await db.execute(text(sql))
            await db.rollback()
    assert len(await _rows(env)) == 1


async def test_deleting_a_user_keeps_their_rows(env):
    async with env.sessions() as db:
        role = Role(name=f"r-{uuid4().hex[:6]}")
        db.add(role)
        await db.flush()
        user = User(username="budi", email="budi@x.test", password_hash="x", role_id=role.id, group_id="blue")
        db.add(user)
        await db.commit()
        uid = user.id
    await audit_log(None, uid, "settings_changed", "settings", "smtp")
    async with env.sessions() as db:
        await db.delete(await db.get(User, uid))
        await db.commit()
    rows = await _rows(env)
    assert rows[0]["actor_name"] == "budi"


async def test_the_verifier_finds_edits_made_with_the_guards_off(env):
    for i in range(4):
        await audit_log(None, None, f"a{i}", "test", str(i))
    async with env.sessions() as db:
        await db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only"))
        await db.execute(text("UPDATE audit_logs SET detail = '{\"forged\": true}' WHERE seq = 2"))
        await db.execute(text("DELETE FROM audit_logs WHERE seq = 3"))
        head = (await db.execute(text("SELECT seq, hash FROM audit_logs WHERE seq = 4"))).first()
        await db.execute(text("DELETE FROM audit_logs WHERE seq = 4"))
        await db.commit()
        result = await audit_chain.verify(db, {"seq": head[0], "hash": head[1]})
    found = {(p["seq"], p["problem"]) for p in result["problems"]}
    assert result["ok"] is False
    assert (2, "content changed after it was written") in found
    assert (4, "a checkpointed row is gone (newest rows deleted)") in found
    assert result["checkpoint"]["status"] == "missing"


async def test_logins_are_audited_with_reason_address_and_user_agent(env):
    async with env.sessions() as db:
        role = Role(name=f"r-{uuid4().hex[:6]}")
        db.add(role)
        await db.flush()
        db.add(User(username="sari", email="sari@x.test", password_hash=hash_password("right-pass"),
                    role_id=role.id, group_id="blue"))
        await db.commit()
    assert (await env.api.post("/api/auth/login", json={"username": "nobody", "password": "x"})).status_code == 401
    assert (await env.api.post("/api/auth/login", json={"username": "sari", "password": "wrong"})).status_code == 401
    assert (await env.api.post("/api/auth/login", json={"username": "sari", "password": "right-pass"})).status_code == 200
    rows = await _rows(env)
    failed = [r for r in rows if r["action"] == "login_failed"]
    assert [r["detail"]["reason"] for r in failed] == ["unknown_user", "bad_password"]
    assert all(r["outcome"] == "failure" and r["ip_address"] == "203.0.113.7" for r in failed)
    assert failed[0]["actor_name"] == "nobody" and failed[0]["user_agent"] == "pytest-browser/1.0"
    ok = [r for r in rows if r["action"] == "login_success"]
    assert ok and ok[0]["request"] == "POST /api/auth/login" and ok[0]["actor_name"] == "sari"


async def test_list_filters_verify_and_denied_access(env):
    await env.api.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    r = await env.api.get("/api/audit-logs", params={"ip": "203.0.113.7", "outcome": "failure"})
    assert r.status_code == 200, r.text
    assert [x["action"] for x in r.json()] == ["login_failed"] and r.json()[0]["seq"] == 1
    csv_text = (await env.api.get("/api/audit-logs/export.csv")).text
    assert "login_failed" in csv_text and "203.0.113.7" in csv_text
    verdict = (await env.api.get("/api/audit-logs/verify")).json()
    assert verdict["ok"] is True and verdict["checked"] == 1

    env.user = _person("analyst", perms=("alerts:read",))
    assert (await env.api.get("/api/audit-logs")).status_code == 403
    rows = await _rows(env)
    denied = [r for r in rows if r["action"] == "permission_denied"]
    assert denied and denied[0]["outcome"] == "denied" and denied[0]["ip_address"] == "203.0.113.7"
    env.user = _person()
    assert (await env.api.delete(f"/api/audit-logs/{uuid4()}")).status_code in (404, 405)  # no such route
