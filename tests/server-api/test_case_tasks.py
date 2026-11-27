"""Case tasks: CRUD, group scoping through the case, and assignee checks."""
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import case_tasks
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Case, CaseTask, Role, User

BLUE_CASE = UUID(int=1)
RED_CASE = UUID(int=2)
BLUE_USER = UUID(int=11)
RED_USER = UUID(int=12)
MANAGE = SimpleNamespace(name='analyst', permissions=[SimpleNamespace(name='cases:manage')])
READ_ONLY = SimpleNamespace(name='viewer', permissions=[])


@pytest.fixture
async def make_client(monkeypatch):
    async def _noop(*_a, **_k):
        return None
    monkeypatch.setattr(case_tasks, 'audit_log', _noop)
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    for model in (Role, User, Case, CaseTask):
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
        db.add(Role(id=1, name='analyst'))
        db.add(User(id=BLUE_USER, username='blue-analyst', email='b@example.test', password_hash='x', role_id=1, group_id='blue'))
        db.add(User(id=RED_USER, username='red-analyst', email='r@example.test', password_hash='x', role_id=1, group_id='red'))
        db.add(Case(id=BLUE_CASE, title='Blue case', group_id='blue', severity='high', status='open', ioc_data={}, search_intel={}))
        db.add(Case(id=RED_CASE, title='Red case', group_id='red', severity='high', status='open', ioc_data={}, search_intel={}))
        await db.commit()
    clients = []

    async def build(role=MANAGE, group='blue'):
        app = FastAPI()
        app.include_router(case_tasks.router)

        async def database():
            async with sessions() as db:
                yield db
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            id=BLUE_USER, username='blue-analyst', group_id=group, role=role)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test')
        clients.append(client)
        return client
    try:
        yield build
    finally:
        for client in clients:
            await client.aclose()
        await engine.dispose()


async def test_create_list_complete_and_delete(make_client):
    client = await make_client()
    r = await client.post(f'/api/cases/{BLUE_CASE}/tasks', json={'title': '  Reset user password ', 'assignee_id': str(BLUE_USER)})
    assert r.status_code == 201, r.text
    task = r.json()
    assert task['title'] == 'Reset user password' and task['done'] is False and task['completed_at'] is None

    r = await client.put(f'/api/cases/{BLUE_CASE}/tasks/{task["id"]}', json={'done': True})
    assert r.status_code == 200 and r.json()['done'] is True and r.json()['completed_at']

    r = await client.put(f'/api/cases/{BLUE_CASE}/tasks/{task["id"]}', json={'done': False, 'clear_assignee': True})
    assert r.json()['completed_at'] is None and r.json()['assignee_id'] is None

    assert len((await client.get(f'/api/cases/{BLUE_CASE}/tasks')).json()) == 1
    assert (await client.delete(f'/api/cases/{BLUE_CASE}/tasks/{task["id"]}')).status_code == 204
    assert (await client.get(f'/api/cases/{BLUE_CASE}/tasks')).json() == []


async def test_other_groups_case_is_not_reachable(make_client):
    client = await make_client()
    assert (await client.get(f'/api/cases/{RED_CASE}/tasks')).status_code == 404
    assert (await client.post(f'/api/cases/{RED_CASE}/tasks', json={'title': 'x'})).status_code == 404


async def test_task_id_from_another_case_is_404(make_client):
    red = await make_client(group='red')
    task = (await red.post(f'/api/cases/{RED_CASE}/tasks', json={'title': 'red task'})).json()
    blue = await make_client()
    assert (await blue.put(f'/api/cases/{BLUE_CASE}/tasks/{task["id"]}', json={'done': True})).status_code == 404


async def test_assignee_must_be_in_the_cases_group(make_client):
    client = await make_client()
    r = await client.post(f'/api/cases/{BLUE_CASE}/tasks', json={'title': 'x', 'assignee_id': str(RED_USER)})
    assert r.status_code == 422


async def test_viewer_can_list_but_not_write(make_client):
    client = await make_client(role=READ_ONLY)
    assert (await client.get(f'/api/cases/{BLUE_CASE}/tasks')).status_code == 200
    assert (await client.post(f'/api/cases/{BLUE_CASE}/tasks', json={'title': 'x'})).status_code == 403


async def test_blank_title_is_rejected(make_client):
    client = await make_client()
    assert (await client.post(f'/api/cases/{BLUE_CASE}/tasks', json={'title': ''})).status_code == 422
