"""POST /api/alerts/bulk-update: one transaction, group-scoped, SLA timestamps."""
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import alerts
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, AlertNote

BLUE = [UUID(int=i) for i in range(1, 4)]
RED = UUID(int=9)
UPDATE = SimpleNamespace(name='analyst', permissions=[SimpleNamespace(name='alerts:update')])


@pytest.fixture
async def setup(monkeypatch):
    async def _noop(*_a, **_k):
        return None
    monkeypatch.setattr(alerts, 'audit_log', _noop)
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    for model in (Alert, AlertNote):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, (JSONB, ARRAY)):
                column.type = JSON()
            elif isinstance(column.type, Uuid):
                column.type = Uuid()
        for constraint in list(table.foreign_key_constraints):
            table.constraints.remove(constraint)
        table.foreign_keys.clear()
        for column in table.columns:
            column.foreign_keys.clear()
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        for alert_id in BLUE:
            db.add(Alert(id=alert_id, title='t', severity='high', status='new', group_id='blue'))
        db.add(Alert(id=RED, title='t', severity='high', status='new', group_id='red'))
        await db.commit()
    app = FastAPI()
    app.include_router(alerts.router)

    async def database():
        async with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID(int=100), username='analyst', group_id='blue', role=UPDATE)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        yield client, sessions
    await engine.dispose()


async def test_updates_own_group_and_skips_others(setup):
    client, sessions = setup
    r = await client.post('/api/alerts/bulk-update', json={'ids': [str(i) for i in BLUE] + [str(RED)], 'status': 'resolved'})
    assert r.status_code == 200, r.text
    assert r.json() == {'updated': 3, 'not_found': [str(RED)]}
    async with sessions() as db:
        rows = {a.id: a for a in (await db.execute(select(Alert))).scalars()}
    for alert_id in BLUE:
        assert rows[alert_id].status == 'resolved'
        assert rows[alert_id].acknowledged_at is not None and rows[alert_id].resolved_at is not None
    assert rows[RED].status == 'new'


async def test_rejects_unknown_status_and_empty_list(setup):
    client, _ = setup
    assert (await client.post('/api/alerts/bulk-update', json={'ids': [str(BLUE[0])], 'status': 'deleted'})).status_code == 422
    assert (await client.post('/api/alerts/bulk-update', json={'ids': [], 'status': 'resolved'})).status_code == 422


async def test_caps_the_batch_size(setup):
    client, _ = setup
    ids = [str(UUID(int=1000 + i)) for i in range(alerts.BULK_MAX + 1)]
    assert (await client.post('/api/alerts/bulk-update', json={'ids': ids, 'status': 'resolved'})).status_code == 422
