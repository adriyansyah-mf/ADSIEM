"""Rule quality in the worker: a suppression counts the alerts it hides and
stops hiding once expired; a rule's level override changes the level its
matches carry. The suppression tests need TEST_DATABASE_URL (disposable
PostgreSQL); each gets its own schema, dropped afterwards."""
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from worker import alert_manager
from worker.models import AlertSuppression
from worker.sigma_engine import SigmaEngine

RULE = """
title: Suspicious Whoami
id: 7d1c9e1a-0000-4000-8000-000000000001
level: medium
logsource: {product: linux}
detection:
  sel: {process: whoami}
  condition: sel
"""


@pytest.fixture
async def sessions(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    from app.core.database import Base
    from app.models.models import AlertSuppression as ApiSuppression

    schema = "rq_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as connection:
        await connection.run_sync(lambda c: Base.metadata.create_all(c, tables=[ApiSuppression.__table__]))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(alert_manager, "AsyncSessionLocal", factory)
    try:
        yield factory
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def _add(sessions, **kw):
    async with sessions() as db:
        row = AlertSuppression(entity_type=kw.pop("entity_type", "ip"), entity_value=kw.pop("entity_value", "10.0.0.5"),
                               group_id=kw.pop("group_id", "blue"), is_active=True, **kw)
        db.add(row)
        await db.commit()
        return row.id


async def _row(sessions, sid):
    async with sessions() as db:
        return (await db.execute(select(AlertSuppression).where(AlertSuppression.id == sid))).scalar_one()


async def test_a_suppression_counts_what_it_hides(sessions):
    sid = await _add(sessions)
    for _ in range(3):
        assert await alert_manager._is_suppressed("blue", "10.0.0.5", "web-01", None, "Any rule")
    row = await _row(sessions, sid)
    assert row.hit_count == 3 and row.last_hit_at is not None
    # another group's alerts are not hidden and not counted
    assert not await alert_manager._is_suppressed("red", "10.0.0.5", "web-01", None, "Any rule")
    assert (await _row(sessions, sid)).hit_count == 3


async def test_an_expired_suppression_stops_hiding(sessions):
    past = await _add(sessions, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert not await alert_manager._is_suppressed("blue", "10.0.0.5", None, None, "Any rule")
    assert (await _row(sessions, past)).hit_count == 0
    future = await _add(sessions, entity_type="rule_title", entity_value="Noisy rule",
                        expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert await alert_manager._is_suppressed("blue", None, None, None, "Noisy rule")
    assert (await _row(sessions, future)).hit_count == 1


def test_a_level_override_changes_the_match_level():
    engine = SigmaEngine(redis=None)
    engine.load_from_yaml_list([RULE], ["r1"], ["high"])
    assert [r.level for r in engine.rules] == ["high"]
    engine.load_from_yaml_list([RULE], ["r1"], [None])
    assert [r.level for r in engine.rules] == ["medium"]
    engine.load_from_yaml_list([RULE], ["r1"])  # callers that pass no overrides keep the rule's level
    assert [r.level for r in engine.rules] == ["medium"]
