# tests/server-api/test_heartbeat_config_hash.int.py
"""Agents (heartbeat.Loop) run their config callback, which hands the web
blocklist, malware hashes and policy versions to their stores, only when
config_hash changes. A version change must therefore change config_hash, or a
new block or policy never reaches a running agent until it restarts."""
import asyncio

import pytest

from app.api.routes import ingest

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


async def heartbeat(env):
    resp = await env.client.post("/api/ingest/heartbeat", json={
        "agent_id": str(env.agents["blue"]), "version": "test"}, headers=BLUE)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture
def versions(monkeypatch):
    current = {"web": "", "malware": "", "policy": "p1", "ip": ""}

    async def web(db, agent):
        return current["web"]

    async def ip(db, agent):
        return current["ip"]

    async def malware(db, agent):
        return current["malware"]

    async def policy(db, group):
        return {"version": current["policy"]}

    monkeypatch.setattr(ingest.web_blocks, "agent_version", web)
    monkeypatch.setattr(ingest.ip_blocks, "agent_version", ip)
    monkeypatch.setattr(ingest.malware_hashes, "agent_version", malware)
    monkeypatch.setattr(ingest.agent_policy, "effective", policy)
    return current


async def test_unchanged_versions_keep_the_hash(evidence_api, versions):
    assert (await heartbeat(evidence_api))["config_hash"] == (await heartbeat(evidence_api))["config_hash"]


@pytest.mark.parametrize("key,field,value", [
    ("web", "web_blocklist_version", "blue:5"),
    ("malware", "malware_hashes_version", "9:alert"),
    ("policy", "policy_version", "p2"),
    ("ip", "ip_blocklist_version", "blue:7:block"),
])
async def test_a_version_change_changes_the_config_hash(evidence_api, versions, key, field, value):
    before = await heartbeat(evidence_api)
    versions[key] = value
    after = await heartbeat(evidence_api)
    assert after[field] == value
    assert after["config_hash"] != before["config_hash"]
