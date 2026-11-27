"""GET /api/alerts: multi-value status/severity, unassigned, free-text q, priority sort."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import alerts
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, Alert, AlertNote

ME = UUID(int=100)
READ = SimpleNamespace(name='analyst', permissions=[SimpleNamespace(name='alerts:read')])
NOW = datetime(2026, 11, 27, 9, 0, tzinfo=timezone.utc)
ROWS = [
    # id, severity, status, assignee, host, ip, minutes ago, group
    (1, 'low', 'new', None, 'web-01', '198.51.100.7', 1, 'blue'),
    (2, 'critical', 'new', None, 'ws-eng-01', None, 30, 'blue'),
    (3, 'high', 'acknowledged', ME, 'dc-01', None, 5, 'blue'),
    (4, 'critical', 'resolved', None, 'ws-eng-01', None, 2, 'blue'),
    (5, 'medium', 'in_progress', None, 'hr-03', None, 10, 'blue'),
    (6, 'critical', 'new', None, 'other', None, 1, 'red'),
]


@pytest.fixture
async def client():
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    for model in (Alert, AlertNote, Agent):
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
        for n, severity, status, assignee, host, ip, ago, group in ROWS:
            db.add(Alert(id=UUID(int=n), title=f'alert {n}', severity=severity, status=status, assignee_id=assignee,
                         hostname=host, source_ip=ip, group_id=group, created_at=NOW - timedelta(minutes=ago)))
        await db.commit()
    app = FastAPI()
    app.include_router(alerts.router)

    async def database():
        async with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=ME, username='analyst', group_id='blue', role=READ)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as http:
        yield http
    await engine.dispose()


def ids(response):
    assert response.status_code == 200, response.text
    return [UUID(item['id']).int for item in response.json()['items']]


async def test_comma_separated_status_and_severity(client):
    assert sorted(ids(await client.get('/api/alerts', params={'status': 'new,acknowledged,in_progress'}))) == [1, 2, 3, 5]
    assert sorted(ids(await client.get('/api/alerts', params={'severity': 'critical,high'}))) == [2, 3, 4]
    # a single value still works as before
    assert ids(await client.get('/api/alerts', params={'status': 'resolved'})) == [4]


async def test_unassigned_and_mine(client):
    assert sorted(ids(await client.get('/api/alerts', params={'unassigned': 'true', 'status': 'new'}))) == [1, 2]
    assert ids(await client.get('/api/alerts', params={'assignee_id': str(ME)})) == [3]


async def test_free_text_matches_title_host_and_ip(client):
    assert ids(await client.get('/api/alerts', params={'q': 'ws-eng'})) == [4, 2]
    assert ids(await client.get('/api/alerts', params={'q': '198.51.100'})) == [1]
    assert ids(await client.get('/api/alerts', params={'q': 'alert 5'})) == [5]


async def test_priority_sort_puts_severity_before_age(client):
    order = ids(await client.get('/api/alerts', params={'sort': 'priority'}))
    assert order == [4, 2, 3, 5, 1]
    assert (await client.get('/api/alerts', params={'sort': 'oldest'})).status_code == 422


async def test_other_groups_stay_hidden(client):
    assert 6 not in ids(await client.get('/api/alerts', params={'severity': 'critical'}))
