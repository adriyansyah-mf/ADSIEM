# tests/server-api/test_agent_policy.int.py
"""Group protection policies: validation, the operator API inside the
caller's group, fallback to the default group and built-in defaults, the
heartbeat version agents follow, their fetch, and the malware action a group
policy sets over the global one."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from app.api.routes import ingest, malware_hashes, policies
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.redis_client import get_redis
from app.services import agent_policy


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    async def redis():
        return evidence_api.redis

    async def audit(*a, **kw):
        evidence_api.audits.append(a)

    monkeypatch.setattr(policies, "audit_log", audit)
    app = FastAPI()
    for r in (policies.router, policies.agent_router, ingest.router, malware_hashes.agent_router):
        app.include_router(r)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_redis] = redis
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    agent_policy.invalidate()
    malware_hashes.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api
    agent_policy.invalidate()


def test_validation():
    p = agent_policy.PolicySettings.model_validate({"exclusions": [
        {"kind": "sha256", "value": "AB" * 32, "scopes": ["malware", "alerts", "malware"]},
        {"kind": "path_prefix", "value": "C:\\Tools\\Sysinternals\\", "scopes": ["alerts"]},
        {"kind": "image", "value": "procexp64.exe", "scopes": ["prevention"]},
        {"kind": "image", "value": "PROCEXP64.EXE", "scopes": ["alerts"]},  # duplicate (case)
    ]})
    assert p.exclusions[0].value == "ab" * 32 and p.exclusions[0].scopes == ["alerts", "malware"]
    assert len(p.exclusions) == 3
    for bad in ({"kind": "sha256", "value": "abc", "scopes": ["alerts"]},
                {"kind": "path_prefix", "value": "tmp/x", "scopes": ["alerts"]},
                {"kind": "image", "value": "x.exe", "scopes": []},
                {"kind": "command_line", "value": "ab", "scopes": ["alerts"]},
                {"kind": "regex", "value": ".*", "scopes": ["alerts"]}):
        with pytest.raises(ValidationError):
            agent_policy.PolicySettings.model_validate({"exclusions": [bad]})
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"ransomware_mode": "nuke"})
    # static ML: detect unless set; its own exclusion scope
    assert agent_policy.PolicySettings.model_validate({}).ml_action == "detect"
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"ml_action": "delete"})
    p = agent_policy.PolicySettings.model_validate({"ml_action": "block", "exclusions": [
        {"kind": "path_prefix", "value": "C:\\Build\\", "scopes": ["ml"]}]})
    assert p.ml_action == "block" and p.exclusions[0].scopes == ["ml"]


async def test_policy_api_scope_and_fallback(api):
    c = api.api
    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    # nothing set: built-in defaults
    got = (await c.get("/api/policies/blue")).json()
    assert got["group"] == "blue" and got["applies"] == "built-in" and not got["own_policy"] and got["settings"]["prevention_enabled"] is True
    assert got["settings"]["malware_action"] is None and got["settings"]["exclusions"] == []

    body = {"prevention_enabled": False, "ransomware_mode": "report", "notify_user": False,
            "exclusions": [{"kind": "image", "value": "backup.exe", "scopes": ["ransomware"], "comment": "nightly"}]}
    r = await c.put("/api/policies/blue", json=body)
    assert r.status_code == 200 and r.json()["own_policy"] and r.json()["settings"]["prevention_enabled"] is False
    assert (await c.put("/api/policies/red", json=body)).status_code == 404  # another group
    assert (await c.get("/api/policies/red")).status_code == 404
    listing = (await c.get("/api/policies")).json()
    assert [g["group"] for g in listing] == ["blue"] and listing[0]["agents"] == 1 and listing[0]["own_policy"]

    api.user = api.make_user(role="analyst", group="blue", perms=())
    assert (await c.put("/api/policies/blue", json=body)).status_code == 403

    # superadmin: a default policy applies to groups without their own
    api.user = api.make_user(role="superadmin", group="default", perms=("agents:manage",))
    assert (await c.put("/api/policies/default", json={"yara_on_access": False})).status_code == 200
    red = (await c.get("/api/policies/red")).json()
    assert red["applies"] == "default" and red["settings"]["yara_on_access"] is False and not red["own_policy"]
    assert (await c.delete("/api/policies/blue")).status_code == 204
    assert (await c.get("/api/policies/blue")).json()["applies"] == "default"
    assert (await c.delete("/api/policies/blue")).status_code == 404
    assert [a[2] for a in api.audits] == ["agent_policy_updated", "agent_policy_updated", "agent_policy_deleted"]


async def test_agents_follow_the_version_and_malware_action(api):
    c = api.api
    blue = {"X-Agent-Token": "blue-token"}
    hb = {"agent_id": str(api.agents["blue"]), "hostname": "blue-host"}
    v0 = (await c.post("/api/ingest/heartbeat", json=hb, headers=blue)).json()["policy_version"]
    pol = (await c.post("/api/ingest/policy", headers=blue)).json()
    assert pol["version"] == v0 and pol["group"] == "built-in"

    api.user = api.make_user(role="superadmin", group="default", perms=("agents:manage",))
    await c.put("/api/policies/blue", json={"malware_action": "block"})
    agent_policy.invalidate()
    malware_hashes.invalidate()
    v1 = (await c.post("/api/ingest/heartbeat", json=hb, headers=blue)).json()["policy_version"]
    assert v1 != v0
    delta = (await c.post("/api/ingest/malware-hashes", json={"since": 0}, headers=blue)).json()
    assert delta["action"] == "block"  # the group's policy over the global "detect"
    red = (await c.post("/api/ingest/malware-hashes", json={"since": 0},
                        headers={"X-Agent-Token": "red-token"})).json()
    assert red["action"] == "detect"
