# tests/worker/test_tor_feed.py
"""Tor exit node feed (worker/tor_feed.py): parsing, the broken-list guard,
and the SQL it writes into the IP IoC blocklist."""
import asyncio
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import httpx  # noqa: E402
import pytest  # noqa: E402

from worker import tor_feed  # noqa: E402
from worker.ip_iocs import ALL_GROUPS, IP_BLOCK_SEQ_LOCK  # noqa: E402

LOOP = asyncio.new_event_loop()


def run(coro):
    return LOOP.run_until_complete(coro)


def exits(n):
    return [f"185.220.{i // 250}.{i % 250 + 1}" for i in range(n)]


def test_parse_keeps_public_addresses_once():
    body = "# Tor exits\n185.220.101.1\n\n185.220.101.1\n10.0.0.1\n127.0.0.1\nnot-an-ip\n2a0b:f4c2::1\n"
    assert tor_feed.parse(body) == ["185.220.101.1/32", "2a0b:f4c2::1/128"]


def mock_client(body, status=200):
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(status, text=body)))


def test_fetch_accepts_a_real_sized_list():
    got = run(tor_feed.fetch(mock_client("\n".join(exits(1200)))))
    assert len(got) == 1200 and got[0] == "185.220.0.1/32"


@pytest.mark.parametrize("body,status", [("\n".join(exits(5)), 200), ("<html>captive portal</html>", 200),
                                         ("", 503)])
def test_fetch_refuses_a_broken_answer(body, status):
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        run(tor_feed.fetch(mock_client(body, status)))


class FakeDB:
    def __init__(self, rowcount=0):
        self.calls, self.committed, self.rowcount = [], False, rowcount

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params))
        return type("R", (), {"rowcount": self.rowcount})()

    async def commit(self):
        self.committed = True


def test_apply_upserts_every_exit_for_every_group_under_the_lock():
    db = FakeDB()
    now = datetime(2026, 11, 17, 1, 0, tzinfo=timezone.utc)
    n = run(tor_feed.apply(db, ["185.220.101.1/32", "185.220.101.2/32"], now))
    assert n == 2 and db.committed
    lock_sql, lock_params = db.calls[0]
    assert "pg_advisory_xact_lock" in lock_sql and lock_params == {"k": IP_BLOCK_SEQ_LOCK}
    upsert_sql, rows = db.calls[1]
    assert "INSERT INTO ip_block_entries" in upsert_sql
    assert {r["cidr"] for r in rows} == {"185.220.101.1/32", "185.220.101.2/32"}
    assert all(r["group"] == ALL_GROUPS and r["source"] == "feed" and r["reason"] == tor_feed.REASON
               and r["expires"] == now + tor_feed.ENTRY_TTL for r in rows)


def test_remove_all_touches_only_active_tor_entries():
    db = FakeDB(rowcount=1200)
    assert run(tor_feed.remove_all(db)) == 1200 and db.committed
    sql, params = db.calls[1]
    assert "status = 'removed'" in sql and "nextval('ip_block_seq')" in sql and "status = 'active'" in sql
    assert params == {"source": "feed", "reason": tor_feed.REASON}
