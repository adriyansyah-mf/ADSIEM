# tests/worker/test_webblock_feeds.int.py
"""Feed upserts into web_block_entries. Needs TEST_DATABASE_URL naming a
disposable PostgreSQL; each test gets its own schema, dropped afterwards."""
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import WebAllowRule, WebBlockEntry

URLHAUS = '''# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-11-01","http://evil.example/a.exe","online","2026-11-08","malware_download","elf","l","r"
"2","2026-11-01","http://cdn.good.example/b.exe","online","2026-11-08","malware_download","","l","r"
"3","2026-11-01","http://10.1.2.3/b.exe","online","2026-11-08","malware_download","","l","r"
'''


@pytest.fixture
async def sessions():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "wbfeed_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {WebBlockEntry.__table__, WebAllowRule.__table__}
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


class FakeRedis:
    def __init__(self):
        self.kv = {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def delete(self, key):
        self.kv.pop(key, None)

    async def lpop(self, key):
        return None


@pytest.fixture
def feeds(sessions, monkeypatch):
    from worker import webblock_feeds
    monkeypatch.setattr(webblock_feeds, "AsyncSessionLocal", sessions)
    return webblock_feeds


async def rows(sessions):
    async with sessions() as db:
        res = await db.execute(text("SELECT domain, status, reason, seq, source, group_id "
                                    "FROM web_block_entries ORDER BY domain"))
        return {r.domain: r for r in res}


async def fetch_urlhaus(_key):
    return URLHAUS


async def test_first_run_inserts_active_and_suppressed(feeds, sessions):
    async with sessions() as db:
        db.add(WebAllowRule(group_id="*", domain="good.example", include_subdomains=True, enabled=True))
        db.add(WebAllowRule(group_id="*", domain="evil.example", include_subdomains=True, enabled=False))
        await db.commit()
    state = await feeds.sync_once(FakeRedis(), "urlhaus", "k", fetch=fetch_urlhaus)
    got = await rows(sessions)
    assert set(got) == {"evil.example", "cdn.good.example"}
    assert got["evil.example"].status == "active" and got["evil.example"].reason == "URLhaus: malware_download (elf)"
    assert got["evil.example"].source == "urlhaus" and got["evil.example"].group_id == "*"
    assert got["cdn.good.example"].status == "suppressed"
    assert got["cdn.good.example"].reason == "allowlisted (good.example)"
    assert (state["entries"], state["suppressed"], state["skipped"], state["status"]) == (1, 1, 1, "ok")


async def test_unchanged_run_keeps_seq_and_refreshes_last_seen(feeds, sessions):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET last_seen_in_feed = now() - interval '1 hour'"))
        await db.commit()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    after = await rows(sessions)
    assert {d: r.seq for d, r in after.items()} == {d: r.seq for d, r in before.items()}
    async with sessions() as db:
        stale = (await db.execute(text("SELECT count(*) FROM web_block_entries "
                                       "WHERE last_seen_in_feed < now() - interval '30 minutes'"))).scalar()
    assert stale == 0


async def test_changed_reason_and_allowlist_bump_seq(feeds, sessions):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)
    async with sessions() as db:
        db.add(WebAllowRule(group_id="*", domain="evil.example", include_subdomains=False, enabled=True))
        await db.commit()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    after = await rows(sessions)
    assert after["evil.example"].status == "suppressed" and after["evil.example"].seq > before["evil.example"].seq
    assert after["cdn.good.example"].seq == before["cdn.good.example"].seq


async def test_absent_for_a_day_is_removed_with_new_seq(feeds, sessions):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET last_seen_in_feed = now() - interval '25 hours' "
                              "WHERE domain = 'evil.example'"))
        await db.commit()

    async def other(_key):
        return URLHAUS.replace("evil.example", "other.example")
    state = await feeds.sync_once(redis, "urlhaus", "k", fetch=other)
    after = await rows(sessions)
    assert after["evil.example"].status == "removed" and after["evil.example"].seq > before["evil.example"].seq
    assert after["other.example"].status == "active"
    assert state["removed"] == 1


async def test_phishtank_and_batches(feeds, sessions, monkeypatch):
    monkeypatch.setattr(feeds, "BATCH", 2)
    data = [{"url": f"http://p{i}.example/x", "verified": "yes", "online": "yes", "target": "T"} for i in range(5)]

    async def fetch(_key):
        return json.dumps(data)
    await feeds.sync_once(FakeRedis(), "phishtank", "k", fetch=fetch)
    got = await rows(sessions)
    assert len(got) == 5 and all(r.source == "phishtank" and r.reason == "PhishTank: phishing (T)" for r in got.values())


async def test_missing_key_writes_nothing(feeds, sessions, monkeypatch):
    async def no_key(_name):
        return ""
    monkeypatch.setattr(feeds, "_key_for", no_key)
    redis = FakeRedis()
    await feeds.run_feed(redis, "urlhaus", set())
    assert json.loads(redis.kv[feeds.STATE_PREFIX + "urlhaus"])["status"] == "missing_key"
    assert await rows(sessions) == {}
