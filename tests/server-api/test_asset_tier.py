"""Asset tier: alerts carry their agent's tier and role; the agent update validates it."""
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import ARRAY, JSON, MetaData, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes import alerts
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, Alert, AlertNote
from app.schemas.schemas import AgentUpdate

DC = UUID(int=1)
LAPTOP = UUID(int=2)
READ = SimpleNamespace(name='analyst', permissions=[SimpleNamespace(name='alerts:read')])


@pytest.fixture
async def client():
    engine = create_async_engine('sqlite+aiosqlite://')
    metadata = MetaData()
    for model in (Agent, Alert, AlertNote):
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
        db.add(Agent(id=DC, name='dc', hostname='DC-01', group_id='blue', token_hash='x', asset_tier=0, asset_role='Domain controller'))
        db.add(Agent(id=LAPTOP, name='lt', hostname='LT-07', group_id='blue', token_hash='x'))
        db.add(Alert(id=UUID(int=10), title='on dc', severity='high', status='new', group_id='blue', agent_id=DC))
        db.add(Alert(id=UUID(int=11), title='on laptop', severity='high', status='new', group_id='blue', agent_id=LAPTOP))
        db.add(Alert(id=UUID(int=12), title='syslog', severity='low', status='new', group_id='blue'))
        await db.commit()
    app = FastAPI()
    app.include_router(alerts.router)

    async def database():
        async with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=UUID(int=99), group_id='blue', role=READ)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as c:
        yield c
    await engine.dispose()


async def test_alert_list_carries_agent_tier_and_role(client):
    r = await client.get('/api/alerts')
    assert r.status_code == 200, r.text
    by_title = {item['title']: item for item in r.json()['items']}
    assert (by_title['on dc']['asset_tier'], by_title['on dc']['asset_role']) == (0, 'Domain controller')
    assert by_title['on laptop']['asset_tier'] is None
    assert by_title['syslog']['asset_tier'] is None


def test_agent_update_validates_tier():
    assert AgentUpdate(asset_tier=3).asset_tier == 3
    with pytest.raises(ValidationError):
        AgentUpdate(asset_tier=4)
    with pytest.raises(ValidationError):
        AgentUpdate(asset_role='x' * 101)
    assert 'clear_asset_tier' not in AgentUpdate(clear_asset_tier=True).model_dump()
