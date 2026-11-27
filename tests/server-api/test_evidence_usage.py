"""GET /api/evidence/usage: per-group usage against the budget, scoped to the caller's group."""
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import ARRAY, JSON, MetaData, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import evidence
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import EvidenceGroupUsage, EvidenceInbox

BUDGET = 1000


def _inbox(group, host, size):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return EvidenceInbox(receipt_id=uuid4(), agent_id=uuid4(), event_id=uuid4(), group_id=group, hostname=host,
                         payload_bytes=size, **{c: v for c, v in _required(now).items()})


def _required(now):
    # fill whatever other NOT NULL columns the inbox has with neutral values
    values = {}
    for column in EvidenceInbox.__table__.columns:
        if column.nullable or column.default is not None or column.server_default is not None:
            continue
        if column.name in {'receipt_id', 'agent_id', 'event_id', 'group_id', 'hostname', 'payload_bytes'}:
            continue
        python_type = getattr(column.type, 'python_type', str)
        values[column.name] = now if python_type is datetime else ('x' if python_type is str else
                                                                  0 if python_type is int else '"{}"')
    return values


@pytest.fixture
async def make_client(monkeypatch):
    monkeypatch.setattr(evidence.settings, 'EVIDENCE_GROUP_BUDGET_BYTES', BUDGET)
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    for model in (EvidenceGroupUsage, EvidenceInbox):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, (JSONB, ARRAY)):
                column.type = JSON()
            elif isinstance(column.type, Uuid):
                column.type = Uuid()
        for index in list(table.indexes):
            table.indexes.discard(index)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as db:
        db.add(EvidenceGroupUsage(group_id='default', payload_bytes=1000))
        db.add(EvidenceGroupUsage(group_id='servers', payload_bytes=300))
        for host, size in (('JIMBE', 700), ('LT-02', 200), ('LT-03', 60), ('LT-04', 40)):
            db.add(_inbox('default', host, size))
        db.add(_inbox('servers', 'DC-01', 300))
        await db.commit()

    async def build(group):
        app = FastAPI()
        app.include_router(evidence.router)

        async def database():
            async with sessions() as db:
                yield db
        role = SimpleNamespace(name='superadmin' if group is None else 'analyst', permissions=[])
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=UUID(int=1), group_id=group or 'default', role=role)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test')
    yield build
    await engine.dispose()


async def test_superadmin_sees_every_group_with_top_hosts(make_client):
    async with await make_client(None) as client:
        r = await client.get('/api/evidence/usage')
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['budget_bytes'] == BUDGET
    default, servers = body['groups']
    assert (default['group_id'], default['percent'], default['full']) == ('default', 100.0, True)
    assert [h['hostname'] for h in default['top_hosts']] == ['JIMBE', 'LT-02', 'LT-03']
    assert (servers['group_id'], servers['percent'], servers['full']) == ('servers', 30.0, False)


async def test_group_user_sees_only_their_group(make_client):
    async with await make_client('servers') as client:
        groups = (await client.get('/api/evidence/usage')).json()['groups']
    assert [g['group_id'] for g in groups] == ['servers']
