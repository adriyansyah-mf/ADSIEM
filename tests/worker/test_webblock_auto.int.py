# tests/worker/test_webblock_auto.int.py
"""Alert auto-block DB writes. Needs TEST_DATABASE_URL naming a disposable
PostgreSQL; each test gets its own schema, dropped afterwards."""
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import Alert, WebAllowRule, WebBlockEntry, WebBlockPolicy, AlertNote
from worker.case_grouping import parse_exclusions


@pytest.fixture
async def sessions():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "wbauto_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {WebBlockEntry.__table__, WebAllowRule.__table__, WebBlockPolicy.__table__,
              Alert.__table__, AlertNote.__table__}
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


@pytest.fixture
async def auto(sessions, monkeypatch):
    from worker import webblock_auto

    monkeypatch.setattr(webblock_auto, "AsyncSessionLocal", sessions)

    async def excl():
        return parse_exclusions("")
    monkeypatch.setattr(webblock_auto.alert_iocs, "_exclusions", excl)
    async with sessions() as db:
        alert = Alert(title="Beacon", severity="high", group_id="g")
        db.add(alert)
        db.add(WebBlockPolicy(group_id="g", enabled=True, alert_enabled=True, alert_block_days=7))
        await db.commit()
        alert_id = str(alert.id)
    return webblock_auto, alert_id


def enrichment(domain="c2.example.com"):
    return SimpleNamespace(iocs=[{"type": "domain", "value": domain}],
                           reputation=[SimpleNamespace(ioc_value=domain, ioc_type="domain", malicious=True)])


async def entries(sessions):
    async with sessions() as db:
        res = await db.execute(text("SELECT domain, status, source, group_id, reason, alert_id, seq, expires_at "
                                    "FROM web_block_entries ORDER BY domain"))
        return list(res)


TAGS = ["attack.command-and-control"]


async def test_blocks_and_writes_note(auto, sessions):
    mod, alert_id = auto
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == ["c2.example.com"]
    (row,) = await entries(sessions)
    assert (row.domain, row.status, row.source, row.group_id) == ("c2.example.com", "active", "alert", "g")
    assert str(row.alert_id) == alert_id and row.reason.startswith("Alert: Beacon")
    async with sessions() as db:
        notes = (await db.execute(text("SELECT content FROM alert_notes"))).scalars().all()
        days = (await db.execute(text("SELECT round(extract(epoch FROM (expires_at - now())) / 86400) "
                                      "FROM web_block_entries"))).scalar()
    assert len(notes) == 1 and "c2.example.com" in notes[0] and "group g" in notes[0]
    assert days == 7


async def test_repeat_keeps_seq_and_extension_bumps_it(auto, sessions):
    mod, alert_id = auto
    await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS)
    (first,) = await entries(sessions)
    async with sessions() as db:  # block about to expire sooner than a fresh one would
        await db.execute(text("UPDATE web_block_entries SET expires_at = expires_at + interval '1 day'"))
        await db.commit()
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == []
    (same,) = await entries(sessions)
    assert same.seq == first.seq
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET expires_at = now() + interval '1 day'"))
        await db.commit()
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == ["c2.example.com"]
    (ext,) = await entries(sessions)
    assert ext.seq > first.seq and ext.expires_at > first.expires_at - __import__("datetime").timedelta(days=1)


async def test_removed_entry_is_reactivated(auto, sessions):
    mod, alert_id = auto
    await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS)
    (first,) = await entries(sessions)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET status = 'removed'"))
        await db.commit()
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == ["c2.example.com"]
    (row,) = await entries(sessions)
    assert row.status == "active" and row.seq > first.seq


async def test_allowlisted_domain_is_not_written(auto, sessions):
    mod, alert_id = auto
    async with sessions() as db:
        db.add(WebAllowRule(group_id="*", domain="example.com", include_subdomains=True, enabled=True))
        await db.commit()
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == []
    assert await entries(sessions) == []


async def test_other_group_allowlist_does_not_apply(auto, sessions):
    mod, alert_id = auto
    async with sessions() as db:
        db.add(WebAllowRule(group_id="other", domain="example.com", include_subdomains=True, enabled=True))
        await db.commit()
    assert await mod.maybe_block(alert_id, "g", "Beacon", "monitor", {}, enrichment(), tags=TAGS) == ["c2.example.com"]
