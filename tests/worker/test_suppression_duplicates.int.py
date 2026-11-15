"""alert_manager._is_suppressed keeps working when several active rows match
(old double clicks, or the same value in a group and in "default"): it used
scalar_one_or_none, which raises MultipleResultsFound and broke alert
creation for every matching alert."""
import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from worker import alert_manager
from worker.models import AlertSuppression, Base


@pytest.fixture(autouse=True)
def _loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def sessions(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "supp_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[AlertSuppression.__table__]))
    made = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(alert_manager, "AsyncSessionLocal", made)
    try:
        yield made
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def test_duplicate_rows_still_suppress(sessions):
    async with sessions() as db:
        for group in ("default", "default", "default", "blue"):  # three clicks, plus the group's own
            db.add(AlertSuppression(id=uuid4(), entity_type="ip", entity_value="0.0.0.0", group_id=group,
                                    is_active=True, reason="Confirmed false positive"))
        await db.commit()
    assert await alert_manager._is_suppressed("blue", "0.0.0.0", None, None,
                                              "Firewall Deny Storm — Port Scan / Flood") is True
    assert await alert_manager._is_suppressed("blue", "198.51.100.7", None, None,
                                              "Firewall Deny Storm — Port Scan / Flood") is False
