# tests/worker/test_alert_iocs_backfill.int.py
"""One-shot backfill of alert_iocs from Postgres (alerts.source_ip and linked
case indicators). Needs TEST_DATABASE_URL naming a disposable PostgreSQL; the
test gets its own schema, dropped afterwards."""
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import Alert, Case, CaseAlert


@pytest.fixture
async def sessions():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "iocs_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {Alert.__table__, Case.__table__, CaseAlert.__table__}
    while True:
        dependencies = {fk.column.table for table in tables for fk in table.foreign_keys}
        if dependencies <= tables:
            break
        tables |= dependencies
    async with engine.begin() as connection:
        await connection.run_sync(lambda c: Base.metadata.create_all(c, tables=list(tables)))
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def test_backfill_indexes_old_alerts_once(sessions, monkeypatch):
    from worker import alert_iocs, database, redis_client, settings_cache
    async with sessions() as db:
        alerts = [Alert(title=f"a{i}", severity="high", group_id="blue", source_ip=ip)
                  for i, ip in enumerate(("45.33.32.1", "10.0.0.1", "45.33.32.3"))]
        db.add_all(alerts)
        await db.flush()
        case = Case(title="c", severity="high", status="open", group_id="blue", alert_id=alerts[0].id)
        db.add(case)
        await db.flush()
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[1].id, status="linked", method="ai", reason="r",
                         confidence=0.9, indicators=["domain:c2.example"], accounts=[]))
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[2].id, status="suggested", method="ai", reason="r",
                         confidence=0.5, indicators=["domain:maybe.example"], accounts=[]))
        await db.commit()

    flags, docs = {}, []

    async def get(key):
        return flags.get(key)

    async def set_(key, value):
        flags[key] = value

    async def get_redis():
        return SimpleNamespace(get=get, set=set_)

    async def index_docs(batch):
        docs.extend(batch)

    async def get_setting(key, default=""):
        return default

    monkeypatch.setattr(database, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(redis_client, "get_redis", get_redis)
    monkeypatch.setattr(settings_cache, "get_setting", get_setting)
    monkeypatch.setattr(alert_iocs, "index_docs", index_docs)

    assert await alert_iocs.backfill(batch=2) == 3
    assert {(d["alert_id"], d["type"], d["value"], d["origin"]) for _, d in docs} == {
        (str(alerts[0].id), "ip", "45.33.32.1", "alert"),
        (str(alerts[1].id), "domain", "c2.example", "alert"),
        (str(alerts[2].id), "ip", "45.33.32.3", "alert"),
    }
    assert await alert_iocs.backfill(batch=2) == 0
