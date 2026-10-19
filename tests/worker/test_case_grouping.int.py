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
    assert _run(ai_analyst._find_campaign_case(["ip:80.94.92.27"], "web01", "g1")) == (None, [])




ATTACKER = "ip:80.94.92.27"


def _case(cid):
    cases, notes = _cases()
    case = next(c for c in cases if str(c.id) == cid)
    return case, [n.content for n in notes if n.case_id == case.id]


def _new(ai_analyst, title, family, host, keys, group, related=None):
    return _run(ai_analyst._create_case_from_verdict(
        alert_id="", title=title, severity="high", verdict="create_case", analysis={"threat_type": "other"},
        enrichment=None, group_id=group, family=family, hostname=host, keys=keys, related=related))


def _join(ai_analyst, cid, title, family, host, keys, merge=None):
    return _run(ai_analyst._join_campaign_case(
        case_id=cid, alert_id="", title=title, triage_notes="notes", severity="high",
        family=family, keys=keys, hostname=host, merge=merge))


def test_one_attacker_across_hosts_is_one_case_that_escalates(db):
    from worker import ai_analyst

    a = _new(ai_analyst, "Successful Login After Brute Force", "initial_access", "web01", [ATTACKER], "g2")
    # the same attacker IP on another host joins the same case
    assert _run(ai_analyst._find_campaign_case([ATTACKER], "web02", "g2")) == (a, [])
    out = _join(ai_analyst, a, "Successful Login After Brute Force", "initial_access", "web02", [ATTACKER])
    assert out == {"escalated": False, "new_host": True}

    # persistence on web02 carries no IOC: it belongs to the campaign already on that host
    assert _run(ai_analyst._find_campaign_case([], "web02", "g2")) == (a, [])
    out = _join(ai_analyst, a, "Cron Persistence", "persistence", "web02", [])
    assert out == {"escalated": True, "new_host": False}

    case, notes = _case(a)
    assert case.severity == "critical" and case.title.startswith("🚨 [ESCALATED]")
    assert case.ioc_data["affected_hosts"] == ["web01", "web02"]
    assert case.ioc_data["attack_family"] == "persistence"
    assert case.ioc_data["families_seen"] == ["initial_access", "persistence"]
    assert any("New affected host: **web02**" in n for n in notes)
    assert any("Kill-chain stage advanced: initial_access → **persistence**" in n for n in notes)


def test_another_attacker_on_the_same_host_is_its_own_linked_case(db):
    from worker import ai_analyst

    a = _new(ai_analyst, "Web Shell Upload", "initial_access", "web05", [ATTACKER], "g4")
    other = "ip:45.155.205.9"
    assert _run(ai_analyst._find_campaign_case([other], "web05", "g4")) == (None, [])  # host alone never joins
    related = _run(ai_analyst._related_open_cases(None, "web05", "g4"))
    assert [r["case_id"] for r in related] == [a]
    b = _new(ai_analyst, "SQL Injection Attempt", "initial_access", "web05", [other], "g4", related=related)
    case, _ = _case(b)
    assert case.ioc_data["related_cases"] == [a] and case.ioc_data["ioc_keys"] == [other]


def test_cases_sharing_an_ioc_are_merged_unless_an_analyst_is_on_them(db):
    from sqlalchemy import update

    from worker import ai_analyst
    from worker.database import AsyncSessionLocal
    from worker.models import Case

    h = "hash:" + "c" * 64
    a = _new(ai_analyst, "Successful Login After Brute Force", "initial_access", "db01", [ATTACKER], "g5")
    c = _new(ai_analyst, "Miner Dropped", "execution", "db02", [h], "g5")
    d = _new(ai_analyst, "C2 Beacon", "command_and_control", "db03", ["domain:x9.top"], "g5")

    async def analyst_takes(cid):
        async with AsyncSessionLocal() as s:
            await s.execute(update(Case).where(Case.id == cid).values(status="in_progress"))
            await s.commit()
    _run(analyst_takes(d))

    # one alert ties all three together: the oldest case keeps it
    found, merge = _run(ai_analyst._find_campaign_case([ATTACKER, h, "domain:x9.top"], "db02", "g5"))
    assert found == a and sorted(merge) == sorted([c, d])
    _join(ai_analyst, a, "Download and Execute", "execution", "db02", [ATTACKER, h, "domain:x9.top"], merge)

    case, notes = _case(a)
    assert case.ioc_data["affected_hosts"] == ["db01", "db02"]
    assert set(case.ioc_data["ioc_keys"]) == {ATTACKER, h, "domain:x9.top"}
    assert case.ioc_data["related_cases"] == [d]
    merged, merged_notes = _case(c)
    assert merged.status == "resolved" and merged.ioc_data["merged_into"] == a
    assert any("Merged" in n for n in merged_notes)
    kept, _ = _case(d)
    assert kept.status == "in_progress" and kept.ioc_data["related_cases"] == [a]  # the analyst's case stays
    # a merged case no longer collects alerts
    assert _run(ai_analyst._find_campaign_case([h], "db09", "g5")) == (a, [])


def test_cases_from_before_campaign_keys_still_match(db):
    from worker import ai_analyst
    from worker.database import AsyncSessionLocal
    from worker.models import Case

    async def legacy(ioc):
        async with AsyncSessionLocal() as s:
            c = Case(title="[AI] SSH Brute Force Attack", severity="high", status="open", created_by_ai=True,
                     group_id="g3", ioc_data=ioc)
            s.add(c)
            await s.commit()
            return str(c.id)
    by_ip = _run(legacy({"source_ip": "80.94.92.99", "threat_type": "brute_force"}))
    by_host = _run(legacy({"source_ip": "10.0.0.9", "hostname": "web09", "threat_type": "brute_force"}))
    assert _run(ai_analyst._find_campaign_case(["ip:80.94.92.99"], "web01", "g3")) == (by_ip, [])
    assert _run(ai_analyst._find_campaign_case([], "web09", "g3")) == (by_host, [])
