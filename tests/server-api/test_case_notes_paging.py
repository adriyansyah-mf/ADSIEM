"""A case page carries its newest notes only; older ones page through /notes.

Campaign cases collected hundreds of AI notes each (~477k rows on one server),
and every case open loaded all of them."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import cases
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, Case, CaseAlert, CaseNote

CASE_ID = UUID(int=7)
NOTES = 250


@pytest.fixture
async def client():
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
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
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    async with sessions() as db:
        db.add(Case(id=CASE_ID, title='Busy campaign', group_id='blue', severity='high', status='open',
                    created_at=start, updated_at=start, ioc_data={}, search_intel={}))
        for i in range(NOTES):
            db.add(CaseNote(case_id=CASE_ID, content=f'note {i}', is_ai_generated=True,
                            created_at=start + timedelta(minutes=i)))
        db.add(Case(id=UUID(int=8), title='Other tenant', group_id='red', severity='high'))
        await db.commit()
    app = FastAPI()
    app.include_router(cases.router)

    async def database():
        async with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        group_id='blue', role=SimpleNamespace(name='analyst'))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as c:
            yield c
    finally:
        await engine.dispose()


async def test_case_carries_the_newest_notes_and_the_total(client):
    r = await client.get(f'/api/cases/{CASE_ID}')
    assert r.status_code == 200
    body = r.json()
    assert body['notes_total'] == NOTES
    assert len(body['notes']) == cases.CASE_NOTES_LIMIT
    contents = {n['content'] for n in body['notes']}
    assert f'note {NOTES - 1}' in contents and f'note {NOTES - cases.CASE_NOTES_LIMIT}' in contents
    assert f'note {NOTES - cases.CASE_NOTES_LIMIT - 1}' not in contents


async def test_older_notes_page_newest_first(client):
    r = await client.get(f'/api/cases/{CASE_ID}/notes', params={'offset': cases.CASE_NOTES_LIMIT, 'limit': 100})
    assert r.status_code == 200
    page = [n['content'] for n in r.json()]
    assert page[0] == f'note {NOTES - cases.CASE_NOTES_LIMIT - 1}'
    assert len(page) == 100
    tail = (await client.get(f'/api/cases/{CASE_ID}/notes', params={'offset': 200, 'limit': 100})).json()
    assert [n['content'] for n in tail][-1] == 'note 0' and len(tail) == NOTES - 200


async def test_notes_of_another_tenant_are_not_found(client):
    assert (await client.get(f'/api/cases/{UUID(int=8)}/notes')).status_code == 404
