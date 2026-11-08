# tests/worker/test_webblock_feeds.int.py
"""Feed upserts into web_block_entries. Needs TEST_DATABASE_URL naming a
disposable PostgreSQL; each test gets its own schema, dropped afterwards."""
import asyncio
import json
import os
from uuid import uuid4

import httpx
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

    async def rpush(self, key, value):
        self.kv.setdefault(key, []).append(value)


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


def settings(monkeypatch, feeds, **values):
    async def get_setting(key, default=""):
        return values.get(key, default)
    monkeypatch.setattr(feeds, "get_setting", get_setting)


def mock_http(monkeypatch, feeds, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(feeds.httpx, "AsyncClient",
                        lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)}))


async def test_http_error_never_leaks_the_phishtank_key(feeds, sessions, monkeypatch):
    settings(monkeypatch, feeds, phishtank_app_key="SECRETKEY123")
    mock_http(monkeypatch, feeds, lambda request: httpx.Response(503))
    redis = FakeRedis()
    await feeds.run_feed(redis, "phishtank", set())
    state = json.loads(redis.kv[feeds.STATE_PREFIX + "phishtank"])
    assert state["status"] == "error" and state["error"] == "HTTP 503"


async def test_transport_error_text_is_redacted(feeds, sessions, monkeypatch):
    settings(monkeypatch, feeds, phishtank_app_key="SECRETKEY123")

    def boom(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")
    mock_http(monkeypatch, feeds, boom)
    redis = FakeRedis()
    await feeds.run_feed(redis, "phishtank", set())
    error = json.loads(redis.kv[feeds.STATE_PREFIX + "phishtank"])["error"]
    assert "SECRETKEY123" not in error and "***" in error


async def test_auth_key_is_not_sent_to_another_host(feeds, monkeypatch):
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("auth-key")))
        if request.url.host == "urlhaus.abuse.ch":
            return httpx.Response(302, headers={"location": "https://elsewhere.example/x"})
        return httpx.Response(200, text="ok")
    mock_http(monkeypatch, feeds, handler)
    assert await feeds.fetch_urlhaus("KEY") == "ok"
    assert seen == [("urlhaus.abuse.ch", "KEY"), ("elsewhere.example", None)]


async def test_empty_feed_is_an_error_and_keeps_rows(feeds, sessions, monkeypatch):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET last_seen_in_feed = now() - interval '48 hours'"))
        await db.commit()

    async def empty(_key):
        return "# nothing\n"
    settings(monkeypatch, feeds, abusech_auth_key="k")
    monkeypatch.setitem(feeds.FETCHERS, "urlhaus", empty)
    await feeds.run_feed(redis, "urlhaus", {"urlhaus"})
    state = json.loads(redis.kv[feeds.STATE_PREFIX + "urlhaus"])
    assert state["status"] == "error" and state["error"] == "feed returned no entries"
    assert {r.status for r in (await rows(sessions)).values()} == {"active"}


async def test_failed_fetch_leaves_rows_intact(feeds, sessions):
    await feeds.sync_once(FakeRedis(), "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)

    async def fail(_key):
        raise RuntimeError("HTTP 500")
    with pytest.raises(RuntimeError):
        await feeds.sync_once(FakeRedis(), "urlhaus", "k", fetch=fail)
    after = await rows(sessions)
    assert {d: (r.status, r.seq) for d, r in after.items()} == {d: (r.status, r.seq) for d, r in before.items()}


async def test_mass_removal_is_guarded(feeds, sessions):
    big = "".join(f'"{i}","d","http://h{i}.example/","online","d","malware_download","","l","r"\n' for i in range(4))
    redis = FakeRedis()

    async def first(_key):
        return big
    await feeds.sync_once(redis, "urlhaus", "k", fetch=first)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET last_seen_in_feed = now() - interval '25 hours' "
                              "WHERE domain <> 'h0.example'"))
        await db.commit()

    async def second(_key):
        return big.splitlines()[0] + "\n" + '"9","d","http://new.example/","online","d","malware_download","","l","r"\n'
    state = await feeds.sync_once(redis, "urlhaus", "k", fetch=second)
    assert state["status"] == "removal_guard" and state["guard"] == {"stale": 3, "active": 5}
    got = await rows(sessions)
    assert got["h1.example"].status == "active" and got["new.example"].status == "active"


async def test_removed_row_returns_with_new_seq(feeds, sessions):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)
    async with sessions() as db:
        await db.execute(text("UPDATE web_block_entries SET status = 'removed' WHERE domain = 'evil.example'"))
        await db.commit()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    after = await rows(sessions)
    assert after["evil.example"].status == "active" and after["evil.example"].seq > before["evil.example"].seq


async def test_changed_sample_url_updates_without_seq_bump(feeds, sessions):
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    before = await rows(sessions)

    async def moved(_key):
        return URLHAUS.replace("evil.example/a.exe", "evil.example/0new.exe")
    await feeds.sync_once(redis, "urlhaus", "k", fetch=moved)
    assert (await rows(sessions))["evil.example"].seq == before["evil.example"].seq
    async with sessions() as db:
        url = (await db.execute(text("SELECT sample_url FROM web_block_entries WHERE domain='evil.example'"))).scalar()
    assert url == "http://evil.example/0new.exe"


async def test_global_allowlisted_domain_stays_suppressed(feeds, sessions):
    async with sessions() as db:
        db.add(WebAllowRule(group_id="*", domain="evil.example", include_subdomains=False, enabled=True))
        await db.commit()
    redis = FakeRedis()
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    first = (await rows(sessions))["evil.example"]
    await feeds.sync_once(redis, "urlhaus", "k", fetch=fetch_urlhaus)
    second = (await rows(sessions))["evil.example"]
    assert first.status == second.status == "suppressed" and first.seq == second.seq


async def test_slow_fetch_times_out(feeds, monkeypatch):
    monkeypatch.setattr(feeds, "TIMEOUT", 0.05)

    async def slow(_key):
        await asyncio.sleep(5)
    with pytest.raises(TimeoutError):
        await feeds.sync_once(FakeRedis(), "urlhaus", "k", fetch=slow)


async def test_sync_request_is_requeued_when_the_feed_lock_is_held(feeds, monkeypatch):
    settings(monkeypatch, feeds, abusech_auth_key="k")
    redis = FakeRedis()
    redis.kv[feeds.LOCK_PREFIX + "urlhaus"] = "1"
    await feeds.run_feed(redis, "urlhaus", {"urlhaus"})
    assert redis.kv[feeds.SYNC_QUEUE] == ["urlhaus"]
