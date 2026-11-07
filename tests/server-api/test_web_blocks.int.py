# tests/server-api/test_web_blocks.int.py
"""Web Protection lists: per-group policy, allowlist, expiry, and the agent
delta sync (a removal propagates, other groups never leak, allowlist and
policy changes force a resync)."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.api.routes import web_protection as routes
from app.core.database import get_db
from app.models.models import WebAllowRule, WebBlockEntry, WebBlockPolicy
from app.services import web_blocks as wb
from worker.web_domains import BUILTIN_ALLOWLIST

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(routes.agent_router)
    app.dependency_overrides[get_db] = database
    wb.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api
    wb.invalidate()


async def add(env, domain, group="blue", source="manual", status="active", expires=None, reason="r"):
    async with env.sessions() as db:
        row = WebBlockEntry(domain=domain, group_id=group, source=source, status=status, expires_at=expires,
                            reason=reason)
        db.add(row)
        await db.commit()
        return row.id


async def set_status(env, entry_id, status):
    async with env.sessions() as db:
        row = await db.get(WebBlockEntry, entry_id)
        row.status, row.seq = status, wb.next_seq()
        await db.commit()
    wb.invalidate()


async def set_policy(env, group, **values):
    async with env.sessions() as db:
        row = await db.get(WebBlockPolicy, group) or WebBlockPolicy(group_id=group)
        for key, value in values.items():
            setattr(row, key, value)
        row.seq = wb.next_seq()
        db.add(row)
        await db.commit()
    wb.invalidate()


async def sync(env, since=0, headers=BLUE):
    r = await env.api.post("/api/ingest/web-blocklist", json={"since": since}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def apply(state, out):
    if out["reset"]:
        state = set()
    for c in out["changes"]:
        (state.add if c["action"] == "block" else state.discard)(c["domain"])
    return state


async def test_disabled_group_gets_nothing(env):
    await add(env, "evil.example")
    out = await sync(env)
    assert out["policy"]["enabled"] is False and out["changes"] == [] and out["version"] == ""
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert await wb.agent_version(db, agent) == ""


async def test_delta_sync_scopes_groups_and_propagates_removals(env):
    await set_policy(env, "blue", enabled=True)
    evil = await add(env, "evil.example")
    await add(env, "red-only.example", group="red")
    await add(env, "feed.example", group="*", source="urlhaus")
    out = await sync(env)
    state = apply(set(), out)
    assert state == {"evil.example"} and out["reset"] is True and out["version"] == str(out["seq"])
    assert out["policy"]["page_html"].startswith("<style>")
    await add(env, "second.example")
    await set_status(env, evil, "removed")
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is False
    assert apply(state, out2) == {"second.example"}
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert await wb.agent_version(db, agent) == out2["version"]


async def test_allowlist_and_policy_changes_force_a_resync(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "second.example")
    await add(env, "feed.example", group="*", source="urlhaus")
    out = await sync(env)
    async with env.sessions() as db:
        db.add(WebAllowRule(group_id="blue", domain="second.example"))
        await wb.mark_rules_changed(db)
        await db.commit()
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is True and apply(set(), out2) == set()
    await set_policy(env, "blue", feed_enabled=True)
    out3 = await sync(env, out2["seq"])
    assert out3["reset"] is True and apply(set(), out3) == {"feed.example"}


async def test_expired_entries_are_removed(env):
    await set_policy(env, "blue", enabled=True)
    entry = await add(env, "old.example", expires=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert apply(set(), await sync(env)) == set()
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, entry)).status == "removed"


async def test_a_domain_stays_blocked_while_any_entry_is_active(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "dup.example", source="manual", reason="analyst")
    alert = await add(env, "dup.example", source="alert", reason="auto")
    out = await sync(env)
    await set_status(env, alert, "removed")
    out2 = await sync(env, out["seq"])
    assert out2["changes"] == [{"domain": "dup.example", "action": "block", "source": "manual", "reason": "analyst"}]


async def test_unapproved_agent_is_refused(env):
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        agent.approved = False
        await db.commit()
    r = await env.api.post("/api/ingest/web-blocklist", json={"since": 0}, headers=BLUE)
    assert r.status_code == 403


async def test_builtin_allowlist_seed_is_idempotent(env):
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
        await wb.seed_builtin_allowlist(db)
        count = (await db.execute(select(func.count()).select_from(WebAllowRule).where(
            WebAllowRule.builtin.is_(True)))).scalar_one()
        assert count == len(BUILTIN_ALLOWLIST)
        assert ("github.com", True) in await wb.allow_rules(db, "blue")


async def test_blocked_domains_respects_group_policy_and_allowlist(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "evil.example")
    await add(env, "red.example", group="red")
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
    await add(env, "github.com")
    async with env.sessions() as db:
        assert await wb.blocked_domains(db, "blue", ["evil.example", "red.example", "github.com"]) == {"evil.example"}
        assert await wb.blocked_domains(db, "red", ["red.example"]) == set()  # red has Web Protection off
        assert await wb.blocked_domains(db, None, ["evil.example", "red.example"]) == {"evil.example", "red.example"}


async def page_through(env, group, limit):
    state, since, cont, rules = set(), 0, False, 0
    pages = []
    while True:
        async with env.sessions() as db:
            out = await wb.delta(db, group, since, cont, limit=limit, rules=rules)
        pages.append(out)
        state = apply(state, out)
        if not cont or out["reset"]:
            rules = out["rules"]
        if not out["more"]:
            return state, out, pages
        since, cont = out["seq"], True


async def test_paged_sync_matches_heartbeat_version(env):
    await set_policy(env, "blue", enabled=True)
    names = {f"d{i}.example" for i in range(5)}
    for n in names:
        await add(env, n)
    state, last, pages = await page_through(env, "blue", 2)
    assert pages[0]["reset"] is True and pages[0]["more"] is True and len(pages) == 3
    assert state == names
    wb.invalidate()
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert await wb.agent_version(db, agent) == str(last["seq"])


async def test_rule_change_mid_paging_restarts_sync(env):
    await set_policy(env, "blue", enabled=True)
    for i in range(5):
        await add(env, f"d{i}.example")
    async with env.sessions() as db:
        p1 = await wb.delta(db, "blue", 0, False, limit=2)
    state = apply(set(), p1)
    delivered = next(iter(state))
    async with env.sessions() as db:
        db.add(WebAllowRule(group_id="blue", domain=delivered))
        await wb.mark_rules_changed(db)
        await db.commit()
    since, rules, saw_reset = p1["seq"], p1["rules"], False
    while True:
        async with env.sessions() as db:
            out = await wb.delta(db, "blue", since, True, limit=2, rules=rules)
        saw_reset = saw_reset or out["reset"]
        state = apply(state, out)
        if not out["more"]:
            break
        since, rules = out["seq"], out["rules"]
    assert saw_reset and delivered not in state and len(state) == 4


async def test_due_expiry_marks_version_plus_read_only(env):
    await set_policy(env, "blue", enabled=True)
    entry = await add(env, "old.example", expires=datetime.now(timezone.utc) - timedelta(minutes=1))
    wb.invalidate()
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert (await wb.agent_version(db, agent)).endswith("+")
        assert not db.new and not db.dirty
        assert (await db.get(WebBlockEntry, entry)).status == "active"
    await sync(env)
    wb.invalidate()
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert not (await wb.agent_version(db, agent)).endswith("+")
        assert (await db.get(WebBlockEntry, entry)).status == "removed"


async def test_agent_version_is_cached_until_invalidated(env):
    await set_policy(env, "blue", enabled=True)
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        first = await wb.agent_version(db, agent)
        await add(env, "new.example")
        assert await wb.agent_version(db, agent) == first
        wb.invalidate()
        assert await wb.agent_version(db, agent) != first


async def test_feed_turned_off_resets_without_feed_domains(env):
    await set_policy(env, "blue", enabled=True, feed_enabled=True)
    await add(env, "feed.example", group="*", source="urlhaus")
    out = await sync(env)
    assert apply(set(), out) == {"feed.example"}
    await set_policy(env, "blue", feed_enabled=False)
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is True and apply({"feed.example"}, out2) == set()


def test_heartbeat_response_field_defaults_empty():
    from app.schemas.schemas import HeartbeatResponse
    assert HeartbeatResponse.model_fields["web_blocklist_version"].default == ""


async def test_seed_bumps_rules_marker_only_when_inserting(env):
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
        first = await wb._rules_seq(db)
    assert first > 0
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
        assert await wb._rules_seq(db) == first
