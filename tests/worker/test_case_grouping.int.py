# tests/worker/test_case_grouping.int.py
"""ai_analyst's case helpers against a real Postgres: the brute-force digest,
family-aware matching, related cases and the post-compromise escalation.

Needs TEST_DATABASE_URL = DATABASE_URL (worker.database binds its engine at import).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def db():
    from sqlalchemy import text

    from worker.database import engine
    from worker.models import Base

    async def setup():
        async with engine.begin() as conn:
            # a fresh schema: server-api's tests use the same database and leave
            # tables (e.g. case_investigations → cases) the worker models don't know
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
    _run(setup())
    yield
    _run(engine.dispose())


def _cases():
    from sqlalchemy import select

    from worker.database import AsyncSessionLocal
    from worker.models import Case, CaseNote

    async def go():
        async with AsyncSessionLocal() as s:
            cases = (await s.execute(select(Case).order_by(Case.created_at))).scalars().all()
            notes = (await s.execute(select(CaseNote))).scalars().all()
            return cases, notes
    return _run(go())


def test_digest_collects_sources_into_one_case_a_day(db):
    from worker import ai_analyst

    ids = {_run(ai_analyst._add_to_bruteforce_digest(
        alert_id="a", title="SSH Brute Force Attack", source_ip=ip, hostname=host, group_id="g1", severity="high"))
        for ip, host in [("80.94.92.27", "web01"), ("45.1.2.3", "web01"), ("80.94.92.27", "db01")]}
    assert len(ids) == 1
    cases, notes = _cases()
    digest = next(c for c in cases if c.group_id == "g1")
    assert digest.ioc_data["sources"] == {"80.94.92.27": 2, "45.1.2.3": 1}
    assert digest.ioc_data["hosts"] == ["web01", "db01"]
    assert "(2 sources, 2 hosts)" in digest.title and digest.severity == "medium"
    assert len([n for n in notes if n.case_id == digest.id]) == 2  # one note per new source
    # digests never absorb other alerts
    assert _run(ai_analyst._find_existing_open_case("80.94.92.27", "web01", "g1", family="credential_access")) is None


def test_family_matching_related_cases_and_escalation(db):
    from worker import ai_analyst

    bf = _run(ai_analyst._create_case_from_verdict(
        alert_id="", title="SSH Brute Force Attack", severity="high", verdict="create_case",
        analysis={"threat_type": "brute_force"}, enrichment=None, group_id="g2",
        family="credential_access", hostname="web02"))
    # same host, same family → joins; another family → no match
    assert _run(ai_analyst._find_existing_open_case(None, "web02", "g2", family="credential_access")) == bf
    assert _run(ai_analyst._find_existing_open_case(None, "web02", "g2", family="persistence")) is None
    related = _run(ai_analyst._related_open_cases(None, "web02", "g2"))
    assert [(r["case_id"], r["family"]) for r in related] == [(bf, "credential_access")]

    pers = _run(ai_analyst._create_case_from_verdict(
        alert_id="", title="Cron Persistence", severity="medium", verdict="create_case",
        analysis={"threat_type": "other"}, enrichment=None, group_id="g2",
        family="persistence", hostname="web02", related=related))
    cases, notes = _cases()
    new = next(c for c in cases if str(c.id) == pers)
    assert new.severity == "critical" and new.title.startswith("🚨 [ESCALATED]")
    assert new.ioc_data["related_cases"] == [bf] and new.ioc_data["attack_family"] == "persistence"
    assert any(str(n.case_id) == pers and "may have succeeded" in n.content for n in notes)
    assert any(str(n.case_id) == bf and "New related case" in n.content for n in notes)


def test_cases_from_before_families_are_classified_by_title(db):
    from sqlalchemy import text

    from worker import ai_analyst
    from worker.database import AsyncSessionLocal
    from worker.models import Case

    async def legacy():
        async with AsyncSessionLocal() as s:
            c = Case(title="[AI] SSH Brute Force Attack", severity="high", status="open", created_by_ai=True,
                     group_id="g3", ioc_data={"source_ip": "198.51.100.7", "threat_type": "brute_force"})
            s.add(c)
            await s.commit()
            return str(c.id)
    old = _run(legacy())
    assert _run(ai_analyst._find_existing_open_case("198.51.100.7", None, "g3", family="credential_access")) == old
    assert _run(ai_analyst._find_existing_open_case("198.51.100.7", None, "g3", family="execution")) is None
