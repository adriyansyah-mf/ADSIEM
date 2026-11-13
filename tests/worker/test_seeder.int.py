# tests/worker/test_seeder.int.py
"""Worker replicas starting together seed rules and decoders once: the
advisory lock in seed_if_empty serialises them (rules.title is not unique, so
before it two replicas could both insert the same rule)."""
import asyncio
import glob
import os
from uuid import uuid4

import pytest
import yaml
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from worker import seeder
from worker.models import Base, Decoder, Rule

ROOT = os.path.join(os.path.dirname(__file__), "../..")


@pytest.fixture(autouse=True)
def _loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def sessions(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "seed_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Rule.__table__, Decoder.__table__]))
    made = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(seeder, "AsyncSessionLocal", made)
    monkeypatch.setattr(seeder, "RULES_DIR", os.path.join(ROOT, "rules"))
    monkeypatch.setattr(seeder, "DECODERS_DIR", os.path.join(ROOT, "decoders"))
    try:
        yield made
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def test_replicas_seeding_together_insert_each_rule_once(sessions):
    # as in production after an upgrade: every decoder already exists (so no
    # replica waits on another's decoder insert) and only rules are new
    async with sessions() as db:
        await seeder._upsert_decoders(db)
        await db.commit()
    await asyncio.gather(*(seeder.seed_if_empty() for _ in range(3)))
    async with sessions() as db:
        dup_rules = (await db.execute(select(Rule.title, func.count()).group_by(Rule.title)
                                      .having(func.count() > 1))).all()
        dup_decoders = (await db.execute(select(Decoder.name, func.count()).group_by(Decoder.name)
                                         .having(func.count() > 1))).all()
        n_rules = (await db.execute(select(func.count()).select_from(Rule))).scalar_one()
    assert dup_rules == [] and dup_decoders == []
    titles = set()
    for path in glob.glob(os.path.join(ROOT, "rules", "*.yaml")):
        doc = next((d for d in yaml.safe_load_all(open(path)) if isinstance(d, dict)), {})
        titles.add(doc.get("title", "Untitled"))
    assert n_rules == len(titles)
