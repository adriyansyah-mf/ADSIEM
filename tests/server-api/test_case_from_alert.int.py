# tests/server-api/test_case_from_alert.int.py
"""Analysts open a case by hand from an alert: the case lands in the alert's
group with its host and source IP, a note records who opened it, the alert's
cases can be listed, and an alert from another group is a 404.
Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import AsyncSessionLocal, Base, engine
    from app.models.models import Role, User

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
        async with AsyncSessionLocal() as db:
            role = Role(name="analyst")
            db.add(role)
            await db.flush()
            user = User(username="ana", email="ana@example.com", password_hash="x", role_id=role.id, group_id="blue")
            db.add(user)
            await db.commit()
            return SimpleNamespace(id=user.id, username="ana", group_id="blue")
    user = _run(setup())
    yield user
    _run(engine.dispose())


def _call(fn, *args, **kwargs):
    from app.core.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as db:
            return await fn(*args, db=db, **kwargs)
    return _run(go())


def _alert(group):
    from app.core.database import AsyncSessionLocal
    from app.models.models import Alert

    async def go():
        async with AsyncSessionLocal() as db:
            a = Alert(title="Web server spawned curl", severity="high", group_id=group,
                      source_ip="203.0.113.9", hostname="web01", mitre_techniques=["T1105"])
            db.add(a)
            await db.commit()
            return a.id
    return _run(go())


def test_case_from_alert_carries_its_context(env):
    from app.api.routes import cases as c
    from app.schemas.schemas import CaseCreate

    alert_id = _alert("blue")
    case = _call(c.create_case, CaseCreate(title="Possible webshell on web01", severity="critical", alert_id=alert_id),
                 BackgroundTasks(), current_user=env, group_filter="blue")
    assert case.group_id == "blue" and case.alert_id == alert_id and case.created_by_ai is False
    assert case.ioc_data["affected_hosts"] == ["web01"] and case.ioc_data["source_ip"] == "203.0.113.9"
    assert case.ioc_data["mitre_techniques"] == ["T1105"]
    assert len(case.notes) == 1 and "created manually by **ana**" in case.notes[0].content
    assert f"/alerts/{alert_id}" in case.notes[0].content

    listed = _call(c.list_cases, current_user=env, group_filter="blue", alert_id=alert_id)
    assert [i.id for i in listed.items] == [case.id]
    assert _call(c.list_cases, current_user=env, group_filter="blue", alert_id=uuid.uuid4()).total == 0


def test_superadmin_case_lands_in_the_alerts_group(env):
    from app.api.routes import cases as c
    from app.schemas.schemas import CaseCreate

    alert_id = _alert("red")
    admin = SimpleNamespace(id=env.id, username="root", group_id="default")
    case = _call(c.create_case, CaseCreate(title="Red team host", alert_id=alert_id),
                 BackgroundTasks(), current_user=admin, group_filter=None)
    assert case.group_id == "red"


def test_alert_from_another_group_is_not_found(env):
    from app.api.routes import cases as c
    from app.schemas.schemas import CaseCreate

    alert_id = _alert("red")
    with pytest.raises(HTTPException) as exc:
        _call(c.create_case, CaseCreate(title="peek", alert_id=alert_id),
              BackgroundTasks(), current_user=env, group_filter="blue")
    assert exc.value.status_code == 404


def test_case_without_alert_uses_the_callers_group(env):
    from app.api.routes import cases as c
    from app.schemas.schemas import CaseCreate

    case = _call(c.create_case, CaseCreate(title="Threat hunt: beaconing"), BackgroundTasks(),
                 current_user=env, group_filter="blue")
    assert case.group_id == "blue" and case.alert_id is None and case.notes == []
