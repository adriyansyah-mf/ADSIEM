"""Exercise case listing with large evidence payloads in an isolated SQLite DB."""
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import cases
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, Case, CaseAlert, CaseNote


@pytest.fixture
async def listing():
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    # Only these tables are queried; SQLite's default FK enforcement is off.
    for model in (Alert, Case, CaseAlert, CaseNote):
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
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    async with sessions() as db:
        alert = Alert(id=uuid4(), title='Source', severity='high', hostname='web01', group_id='blue')
        db.add(alert)
        for i in range(30):
            case = Case(id=UUID(int=i + 1), title=f'Case {i}', group_id='blue', severity='high',
                        status='open', alert_id=alert.id, created_at=stamp, updated_at=stamp,
                        description='D' * 20000, ai_reasoning='R' * 20000,
                        ioc_data={'evidence': 'I' * 20000}, search_intel={'results': 'S' * 20000})
            db.add(case)
            db.add(CaseNote(case_id=case.id, content='N' * 20000))
        db.add(Case(title='Other tenant', group_id='red', severity='high'))
        await db.commit()
    statements = []
    event.listen(engine.sync_engine, 'before_cursor_execute',
                 lambda conn, cursor, statement, params, ctx, many: statements.append(statement))
    app = FastAPI()
    app.include_router(cases.router)
    async def database():
        async with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        group_id='blue', role=SimpleNamespace(name='analyst'))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            yield client, statements, str(alert.id)
    finally:
        await engine.dispose()


async def test_summary_stays_small_without_loading_notes_or_intel(listing):
    client, statements, _ = listing
    response = await client.get('/api/cases', params={'summary': 'true'})
    assert response.status_code == 200
    data = response.json()
    assert data['total'] == 30
    assert len(data['items']) == 25
    assert len(response.content) < 50000
    assert all(row['group_id'] == 'blue' for row in data['items'])
    assert all('notes' not in row and 'ioc_data' not in row and 'search_intel' not in row for row in data['items'])
    assert len(statements) == 2
    assert not any('case_notes' in sql for sql in statements)
    assert 'ORDER BY' not in statements[0]


async def test_summary_pagination_and_filters_preserve_scope(listing):
    client, _, alert_id = listing
    params = {'summary': 'true', 'page_size': 25, 'status': 'open', 'severity': 'high',
              'hostname': 'web01', 'alert_id': alert_id, 'search': 'Case',
              'start_time': '2025-12-01T00:00:00Z', 'end_time': '2026-02-01T00:00:00Z'}
    first = (await client.get('/api/cases', params=params)).json()
    second = (await client.get('/api/cases', params={**params, 'page': 2})).json()
    assert first['total'] == second['total'] == 30
    ids = [row['id'] for row in first['items'] + second['items']]
    assert len(ids) == len(set(ids)) == 30
    assert ids == [str(UUID(int=i)) for i in range(30, 0, -1)]
    empty = (await client.get('/api/cases', params={**params, 'status': 'closed'})).json()
    assert empty['total'] == 0 and empty['items'] == []


async def test_legacy_list_keeps_full_details(listing):
    client, _, _ = listing
    response = await client.get('/api/cases', params={'page_size': 1})
    assert response.status_code == 200
    row = response.json()['items'][0]
    assert len(row['notes'][0]['content']) == 20000
    assert len(row['description']) == 20000
    assert len(row['ioc_data']['evidence']) == 20000


@pytest.mark.parametrize('params', [{'page': 0}, {'page_size': 0}, {'page_size': 101}])
async def test_listing_rejects_unbounded_or_invalid_pages(listing, params):
    client, statements, _ = listing
    response = await client.get('/api/cases', params=params)
    assert response.status_code == 422
    assert statements == []


async def test_detail_keeps_full_investigation_after_loading_summary(listing):
    client, _, _ = listing
    summary = (await client.get('/api/cases', params={'summary': 'true'})).json()['items'][0]
    response = await client.get(f"/api/cases/{summary['id']}")
    assert response.status_code == 200
    detail = response.json()
    assert len(summary['description']) == len(summary['ai_reasoning']) == 500
    assert len(detail['description']) == len(detail['ai_reasoning']) == 20000
    assert len(detail['notes'][0]['content']) == 20000
    assert len(detail['search_intel']['results']) == 20000
