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

from app.api.routes import agents, ingest, malware_hashes, policies
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.redis_client import get_redis
from app.models import models
from app.services import agent_policy
from app.services.agent_config import config_version_of


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
    for r in (policies.router, policies.agent_router, ingest.router, malware_hashes.agent_router, agents.router):
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
    # IOA: detect unless off; no block mode yet; its own exclusion scope
    assert agent_policy.PolicySettings.model_validate({}).ioa == "detect"
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"ioa": "block"})
    p = agent_policy.PolicySettings.model_validate({"ioa": "off", "exclusions": [
        {"kind": "image", "value": "sccm.exe", "scopes": ["ioa"]}]})
    assert p.ioa == "off" and p.exclusions[0].scopes == ["ioa"]


def test_browser_policy_validation():
    assert agent_policy.PolicySettings.model_validate({}).browser_policy == "off"
    assert agent_policy.PolicySettings.model_validate({"browser_policy": "on"}).browser_policy == "on"
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"browser_policy": "block"})


def test_ransomware_rollback_validation():
    s = agent_policy.PolicySettings.model_validate({})
    assert s.ransomware_rollback == "off" and s.rollback_paths == []
    s = agent_policy.PolicySettings.model_validate({"ransomware_rollback": "auto",
                                                    "rollback_paths": ["/srv/data", " D:\\Shares\\Finance ", "",
                                                                       "/srv/data"]})
    assert s.rollback_paths == ["/srv/data", "D:\\Shares\\Finance"]
    for bad in (["relative/path"], ["/home/*/Documents"], ["/"], ["C:\\"]):
        with pytest.raises(ValidationError):
            agent_policy.PolicySettings.model_validate({"rollback_paths": bad})
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"ransomware_rollback": "on"})


def test_dns_sinkhole_validation():
    assert agent_policy.PolicySettings.model_validate({}).dns_sinkhole == "off"
    assert agent_policy.PolicySettings.model_validate({"dns_sinkhole": "on"}).dns_sinkhole == "on"
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"dns_sinkhole": "all"})


def test_yara_action_and_exec_scan_validation():
    # a YARA match is only reported unless a group quarantines; critical is the default threshold
    d = agent_policy.PolicySettings.model_validate({})
    assert (d.yara_action, d.yara_quarantine_level, d.exec_scan) == ("detect", "critical", "on")
    p = agent_policy.PolicySettings.model_validate(
        {"yara_action": "quarantine", "yara_quarantine_level": "high", "exec_scan": "off"})
    assert (p.yara_action, p.yara_quarantine_level, p.exec_scan) == ("quarantine", "high", "off")
    for bad in ({"yara_action": "block"}, {"yara_quarantine_level": "medium"}, {"exec_scan": "maybe"}):
        with pytest.raises(ValidationError):
            agent_policy.PolicySettings.model_validate(bad)


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


def test_policy_settings_carry_the_agent_config_without_nulls():
    s = agent_policy.PolicySettings.model_validate({})
    assert s.agent_config is None and s.model_dump()["agent_config"] is None
    d = agent_policy.PolicySettings.model_validate(
        {"agent_config": {"fim": {"enabled": False}, "etw": {}, "netwatch": {"enabled": None}}}).model_dump()
    assert d["agent_config"] == {"fim": {"enabled": False}}
    assert agent_policy.PolicySettings.model_validate({"agent_config": {"fim": {}}}).model_dump()["agent_config"] is None
    with pytest.raises(ValidationError):
        agent_policy.PolicySettings.model_validate({"agent_config": {"etw": {"mode": "sometimes"}}})
    # a policy without an overlay keeps the version it had before overlays existed
    assert agent_policy.version_of({"ioa": "off", "agent_config": None}) == agent_policy.version_of({"ioa": "off"})


def test_for_agent_puts_config_version_on_top():
    base = agent_policy.PolicySettings.model_validate({}).model_dump()
    eff = {"group": "g", "settings": base, "version": "v", "config_version": "", "ml_false_positives": []}
    out = agent_policy.for_agent(eff)
    assert out["config_version"] == "" and "agent_config" not in out["settings"]
    overlay = {"fim": {"enabled": False}}
    out = agent_policy.for_agent({**eff, "settings": {**base, "agent_config": overlay},
                                  "config_version": config_version_of(overlay)})
    assert out["config_version"] == config_version_of(overlay) and out["settings"]["agent_config"] == overlay


def _no_nulls(v) -> bool:
    if isinstance(v, dict):
        return all(x is not None and _no_nulls(x) for x in v.values())
    if isinstance(v, list):
        return all(_no_nulls(x) for x in v)
    return True


async def test_agent_config_overlay_reaches_the_agent(api):
    c = api.api
    blue = {"X-Agent-Token": "blue-token"}
    pol = (await c.post("/api/ingest/policy", headers=blue)).json()
    assert pol["config_version"] == "" and "agent_config" not in pol["settings"]

    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    for bad in ({"server": {"url": "http://siem.example.com"}}, {"server": {"heartbeat_interval": 5}},
                {"anti_tamper": {"unlock_service": True}}, {"agent": {"token": "x"}}, {"etw": {"mode": "x"}}):
        assert (await c.put("/api/policies/blue", json={"agent_config": bad})).status_code == 422, bad

    overlay = {"fim": {"enabled": False}, "etw": {"mode": "off"}, "server": {"heartbeat_interval": 60},
               "detect": {"rules": []}}
    r = await c.put("/api/policies/blue", json={"agent_config": {
        **overlay, "netwatch": {}, "yara": {"max_file_size_mb": None}}})
    assert r.status_code == 200 and r.json()["settings"]["agent_config"] == overlay
    async with api.sessions() as db:
        assert (await db.get(models.AgentPolicy, "blue")).settings["agent_config"] == overlay  # stored clean

    pol = (await c.post("/api/ingest/policy", headers=blue)).json()
    assert pol["config_version"] == config_version_of(overlay) != ""
    assert pol["settings"]["agent_config"] == overlay and _no_nulls(pol["settings"]["agent_config"])
    # the red group has no overlay
    red = (await c.post("/api/ingest/policy", headers={"X-Agent-Token": "red-token"})).json()
    assert red["config_version"] == "" and "agent_config" not in red["settings"]


async def test_ml_false_positive_changes_the_version_not_the_config_version(api):
    c = api.api
    blue = {"X-Agent-Token": "blue-token"}
    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    assert (await c.put("/api/policies/blue", json={"agent_config": {"fim": {"enabled": False}}})).status_code == 200
    before = (await c.post("/api/ingest/policy", headers=blue)).json()
    async with api.sessions() as db:
        db.add(models.MlFalsePositive(sha256="ab" * 32))
        await db.commit()
    agent_policy.invalidate()
    after = (await c.post("/api/ingest/policy", headers=blue)).json()
    assert after["version"] != before["version"]
    assert after["config_version"] == before["config_version"] != ""


async def test_heartbeat_stores_the_config_status(api):
    c = api.api
    blue = {"X-Agent-Token": "blue-token"}
    hb = {"agent_id": str(api.agents["blue"]), "hostname": "blue-host"}

    async def row():
        async with api.sessions() as db:
            return await db.get(models.Agent, api.agents["blue"])

    r = await c.post("/api/ingest/heartbeat", headers=blue,
                     json={**hb, "config_version": "0123456789abcdef", "config_error": "server.url: host must stay x"})
    assert r.status_code == 200
    a = await row()
    assert (a.config_version, a.config_error) == ("0123456789abcdef", "server.url: host must stay x")
    # a heartbeat without them keeps what was stored
    assert (await c.post("/api/ingest/heartbeat", json=hb, headers=blue)).status_code == 200
    a = await row()
    assert (a.config_version, a.config_error) == ("0123456789abcdef", "server.url: host must stay x")
    # an overlong error is clipped and a bad version dropped; the heartbeat itself still goes through
    r = await c.post("/api/ingest/heartbeat", headers=blue,
                     json={**hb, "config_version": "x" * 65, "config_error": "e" * 600})
    assert r.status_code == 200
    a = await row()
    assert a.config_version == "0123456789abcdef" and a.config_error == "e" * 500


async def test_agent_api_shows_the_expected_config_version(api):
    c = api.api
    api.user = api.make_user(role="superadmin", group="default", perms=("agents:manage",))
    overlay = {"memory_sweep": {"interval_minutes": 30}}
    assert (await c.put("/api/policies/blue", json={"agent_config": overlay})).status_code == 200
    await c.post("/api/ingest/heartbeat", headers={"X-Agent-Token": "blue-token"},
                 json={"agent_id": str(api.agents["blue"]), "hostname": "blue-host", "config_version": ""})
    got = (await c.get(f"/api/agents/{api.agents['blue']}")).json()
    assert got["config_expected"] == config_version_of(overlay) and got["config_version"] == ""
    listing = {a["name"]: a for a in (await c.get("/api/agents")).json()["items"]}
    assert listing["blue"]["config_expected"] == config_version_of(overlay)
    assert listing["red"]["config_expected"] == "" and listing["red"]["config_version"] is None
