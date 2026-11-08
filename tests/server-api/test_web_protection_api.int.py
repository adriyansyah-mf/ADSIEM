# tests/server-api/test_web_protection_api.int.py
"""Web Protection dashboard API: manual block/unblock, allowlist, policy and
block page — every route scoped to the caller's group."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import web_protection as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import WebAllowRule, WebBlockEntry
from app.services import web_blocks as wb

MANAGE = ("alerts:read", "agents:manage")


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    audits = []

    async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None, **kwargs):
        audits.append((action, resource_id))

    monkeypatch.setattr(routes, "audit_log", audit)
    evidence_api.user = evidence_api.make_user(perms=MANAGE)
    evidence_api.audit_calls = audits
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with evidence_api.sessions() as db:
        await wb.seed_builtin_allowlist(db)
    wb.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def test_manual_block_normalises_and_audits(env):
    r = await env.api.post("/api/web-blocks", json={"value": "https://Evil.example/login", "reason": "phishing"})
    assert r.status_code == 201, r.text
    assert r.json()["domain"] == "evil.example" and r.json()["group_id"] == "blue" and r.json()["source"] == "manual"
    assert ("web_block.add", r.json()["id"]) in env.audit_calls


async def test_ip_and_allowlisted_values_are_refused(env):
    r = await env.api.post("/api/web-blocks", json={"value": "45.33.32.156"})
    assert r.status_code == 422 and "IP addresses cannot be web-blocked" in r.json()["detail"]
    r = await env.api.post("/api/web-blocks", json={"value": "raw.github.com"})
    assert r.status_code == 409 and "github.com" in r.json()["detail"]


async def test_unblock_and_reblock_reuse_the_entry(env):
    created = (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).json()
    assert (await env.api.delete(f"/api/web-blocks/{created['id']}")).json() == {"status": "removed"}
    again = (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).json()
    assert again["id"] == created["id"] and again["status"] == "active"


async def test_unblocking_a_feed_entry_allowlists_it_for_the_group(env):
    async with env.sessions() as db:
        entry = WebBlockEntry(domain="feed.example", group_id="*", source="urlhaus", reason="feed")
        db.add(entry)
        await db.commit()
    assert (await env.api.delete(f"/api/web-blocks/{entry.id}")).json() == {"status": "allowlisted"}
    items = (await env.api.get("/api/web-allowlist")).json()["items"]
    assert any(i["domain"] == "feed.example" and i["group_id"] == "blue" for i in items)
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, entry.id)).status == "active"


async def test_global_unblock_of_a_feed_entry_adds_a_global_rule(env):
    env.user = env.make_user(role="superadmin")
    async with env.sessions() as db:
        entry = WebBlockEntry(domain="feed2.example", group_id="*", source="urlhaus", reason="feed")
        db.add(entry)
        await db.commit()
    assert (await env.api.delete(f"/api/web-blocks/{entry.id}")).json() == {"status": "removed"}
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, entry.id)).status == "removed"
        rule = (await db.execute(select(WebAllowRule).where(
            WebAllowRule.group_id == "*", WebAllowRule.domain == "feed2.example"))).scalar_one()
        assert rule.enabled and not rule.include_subdomains


async def test_groups_cannot_see_or_change_each_other(env):
    async with env.sessions() as db:
        red = WebBlockEntry(domain="red.example", group_id="red", source="manual")
        db.add(red)
        await db.commit()
    listed = (await env.api.get("/api/web-blocks")).json()["items"]
    assert all(i["group_id"] in ("blue", "*") for i in listed)
    assert (await env.api.delete(f"/api/web-blocks/{red.id}")).status_code == 404
    assert (await env.api.post("/api/web-blocks", json={"value": "x.example", "group_id": "red"})).status_code == 404
    assert (await env.api.get("/api/web-block-policies/red")).status_code == 404


async def test_changes_need_agents_manage(env):
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).status_code == 403
    assert (await env.api.get("/api/web-blocks")).status_code == 200


async def test_allowlist_crud_and_builtin_protection(env):
    r = await env.api.post("/api/web-allowlist", json={"domain": "Intranet.Example", "include_subdomains": True})
    assert r.status_code == 201 and r.json()["domain"] == "intranet.example"
    rule_id = r.json()["id"]
    assert (await env.api.patch(f"/api/web-allowlist/{rule_id}", json={"enabled": False})).json()["enabled"] is False
    assert (await env.api.delete(f"/api/web-allowlist/{rule_id}")).status_code == 200
    builtin = next(i for i in (await env.api.get("/api/web-allowlist")).json()["items"] if i["domain"] == "github.com")
    assert (await env.api.delete(f"/api/web-allowlist/{builtin['id']}")).status_code == 403
    assert (await env.api.patch(f"/api/web-allowlist/{builtin['id']}", json={"enabled": False})).status_code == 403
    env.user = env.make_user(role="superadmin")
    assert (await env.api.delete(f"/api/web-allowlist/{builtin['id']}")).status_code == 409
    assert (await env.api.patch(f"/api/web-allowlist/{builtin['id']}", json={"enabled": False})).json()["enabled"] is False


async def test_allowlist_change_bumps_the_rules_marker(env):
    async with env.sessions() as db:
        before = await wb._rules_seq(db, "blue")
    await env.api.post("/api/web-allowlist", json={"domain": "intranet.example"})
    async with env.sessions() as db:
        assert await wb._rules_seq(db, "blue") > before


async def test_policy_defaults_save_sanitises_and_preview(env):
    policy = (await env.api.get("/api/web-block-policies/blue")).json()
    assert policy["enabled"] is False and policy["custom_page"] is False and "{{domain}}" in policy["page_html"]
    body = {"enabled": True, "feed_enabled": False, "alert_enabled": False, "alert_block_days": 14,
            "max_entries": 1000, "contact": "soc@corp.example",
            "page_html": "<h1>Blocked {{domain}}</h1><script>alert(1)</script>"}
    saved = (await env.api.put("/api/web-block-policies/blue", json=body)).json()
    assert saved["enabled"] is True and saved["custom_page"] is True and "<script" not in saved["page_html"]
    preview = (await env.api.post("/api/web-block-policies/blue/preview", json={"page_html": "<p>{{domain}}</p>"})).json()
    assert preview["html"].startswith("<!doctype html>") and "malicious.example" in preview["html"]
    reset = (await env.api.put("/api/web-block-policies/blue", json={**body, "page_html": None})).json()
    assert reset["custom_page"] is False
    bad = await env.api.put("/api/web-block-policies/blue", json={**body, "max_entries": 10})
    assert bad.status_code == 422


async def test_concurrent_upserts_never_500(env):
    blocks = await asyncio.gather(*(env.api.post("/api/web-blocks", json={"value": "race.example"}) for _ in range(6)))
    assert {r.status_code for r in blocks} <= {201, 409}
    rules = await asyncio.gather(*(env.api.post("/api/web-allowlist", json={"domain": "race2.example"}) for _ in range(6)))
    assert {r.status_code for r in rules} <= {201, 409}
    assert any(r.status_code == 201 for r in blocks) and any(r.status_code == 201 for r in rules)


async def test_group_ids_are_bounded(env):
    env.user = env.make_user(role="superadmin")
    assert (await env.api.put("/api/web-block-policies/" + "g" * 101, json={"enabled": True})).status_code == 422
    assert (await env.api.post("/api/web-blocks", json={"value": "x.example", "group_id": "g" * 101})).status_code == 422


async def test_bulk_block_reports_per_item_errors(env):
    r = await env.api.post("/api/web-blocks/bulk", json={
        "action": "block", "values": ["ok.example", "45.33.32.156", "raw.github.com"], "reason": "x"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["done"] == 1 and len(out["errors"]) == 2
    errors = {e["value"]: e["detail"] for e in out["errors"]}
    assert "IP addresses cannot be web-blocked" in errors["45.33.32.156"]
    assert "allowlisted" in errors["raw.github.com"]
    assert sum(1 for a, _ in env.audit_calls if a == "web_block.add") == 1


async def test_bulk_unblock_skips_foreign_group(env):
    async with env.sessions() as db:
        mine = WebBlockEntry(domain="mine.example", group_id="blue", source="manual")
        red = WebBlockEntry(domain="red.example", group_id="red", source="manual")
        db.add_all([mine, red])
        await db.commit()
    r = await env.api.post("/api/web-blocks/bulk", json={"action": "unblock", "ids": [str(mine.id), str(red.id)]})
    out = r.json()
    assert out["done"] == 1 and len(out["errors"]) == 1 and "not found" in out["errors"][0]["detail"].lower()
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, red.id)).status == "active"
        assert (await db.get(WebBlockEntry, mine.id)).status == "removed"


async def test_bulk_limits_and_permission(env):
    r = await env.api.post("/api/web-blocks/bulk", json={"action": "block", "values": ["a.example"] * 501})
    assert r.status_code == 422
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.post("/api/web-blocks/bulk", json={"action": "block", "values": ["a.example"]})).status_code == 403


async def test_expiry_in_the_past_is_rejected(env):
    r = await env.api.post("/api/web-blocks", json={"value": "x.example", "expires_at": "2020-01-01T00:00:00Z"})
    assert r.status_code == 422 and "future" in r.text
    r = await env.api.post("/api/web-blocks/bulk", json={"action": "block", "values": ["x.example"],
                                                         "expires_at": "2020-01-01T00:00:00Z"})
    assert r.status_code == 422


async def test_allowlist_and_policy_changes_are_audited(env):
    rule = (await env.api.post("/api/web-allowlist", json={"domain": "intranet.example"})).json()
    assert ("web_allowlist.add", rule["id"]) in env.audit_calls
    await env.api.put("/api/web-block-policies/blue", json={"enabled": True})
    assert ("web_block_policy.update", "blue") in env.audit_calls


async def test_settings_api_hides_rules_markers(env):
    from fastapi import BackgroundTasks, HTTPException

    from app.api.routes import settings as settings_routes
    from app.models.models import PlatformSetting
    from app.schemas.schemas import SettingUpdate
    async with env.sessions() as db:
        db.add_all([PlatformSetting(key="web_block_rules_seq:blue", value="5", is_secret=False),
                    PlatformSetting(key="visible_setting", value="1", is_secret=False)])
        await db.commit()
        listed = await settings_routes.list_settings(db, env.user)
        keys = {s.key for s in listed}
        assert "visible_setting" in keys and not any(k.startswith("web_block_rules_seq") for k in keys)
        with pytest.raises(HTTPException) as exc:
            await settings_routes.update_setting("web_block_rules_seq:blue", SettingUpdate(value="9"),
                                                 BackgroundTasks(), db, env.user)
        assert exc.value.status_code == 404
