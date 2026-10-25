# tests/server-api/test_yara_ruleset.int.py
"""Agents learn the enabled YARA rule set's hash from the heartbeat and
fetch the rules from POST /api/ingest/yara-rules when it changes."""
import asyncio

import pytest

from app.models import models
from app.services import yara_ruleset

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    # pytest-asyncio 0.24 runs the test on the *current* loop; modules run
    # earlier in the session (asyncio.run, private loops) can leave none.
    asyncio.set_event_loop(event_loop)
    yield


async def heartbeat(env):
    resp = await env.client.post("/api/ingest/heartbeat", json={
        "agent_id": str(env.agents["blue"]), "version": "test"}, headers=BLUE)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def add_rule(env, name, content, enabled=True):
    async with env.sessions() as db:
        db.add(models.YaraRule(name=name, content=content, is_enabled=enabled))
        await db.commit()
    yara_ruleset.invalidate()


async def test_no_rules_means_empty_hash(evidence_api):
    yara_ruleset.invalidate()
    assert (await heartbeat(evidence_api))["yara_rules_hash"] == ""
    resp = await evidence_api.client.post("/api/ingest/yara-rules", json={}, headers=BLUE)
    assert resp.status_code == 200
    assert resp.json() == {"hash": "", "rules": []}


async def test_hash_and_rules_follow_enabled_rules(evidence_api):
    yara_ruleset.invalidate()
    before = await heartbeat(evidence_api)
    await add_rule(evidence_api, "on", "rule on { condition: true }")
    await add_rule(evidence_api, "off", "rule off { condition: true }", enabled=False)
    after = await heartbeat(evidence_api)
    assert after["yara_rules_hash"] not in ("", before["yara_rules_hash"])
    # The rule set is part of the config hash, so the agent's config
    # callback runs and picks up the new hash.
    assert after["config_hash"] != before["config_hash"]

    resp = await evidence_api.client.post("/api/ingest/yara-rules", json={"loaded_hash": ""}, headers=BLUE)
    body = resp.json()
    assert body["hash"] == after["yara_rules_hash"]
    assert [r["name"] for r in body["rules"]] == ["on"]
    assert body["rules"][0]["content"] == "rule on { condition: true }"

    # Same rules, same hash.
    yara_ruleset.invalidate()
    assert (await heartbeat(evidence_api))["yara_rules_hash"] == after["yara_rules_hash"]


async def test_requires_an_approved_agent(evidence_api):
    resp = await evidence_api.client.post("/api/ingest/yara-rules", json={}, headers={"X-Agent-Token": "nope"})
    assert resp.status_code in (401, 403)
    async with evidence_api.sessions() as db:
        agent = await db.get(models.Agent, evidence_api.agents["blue"])
        agent.approved = False
        await db.commit()
    resp = await evidence_api.client.post("/api/ingest/yara-rules", json={}, headers=BLUE)
    assert resp.status_code == 403


def test_ruleset_hash_is_order_independent():
    a = {"id": "1", "name": "a", "content": "x"}
    b = {"id": "2", "name": "b", "content": "y"}
    assert yara_ruleset.ruleset_hash([a, b]) == yara_ruleset.ruleset_hash([b, a])
    assert yara_ruleset.ruleset_hash([a]) != yara_ruleset.ruleset_hash([dict(a, content="z")])
    assert yara_ruleset.ruleset_hash([]) == ""
