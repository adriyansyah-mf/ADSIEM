# tests/server-api/test_hygiene_network.int.py
"""Hygiene snapshots keep the agent's network identity (interfaces, gateway,
DNS, sessions) and add where the report came from, so an IP in an alert can
be traced to a host."""
import httpx
import pytest
from sqlalchemy import select

NETWORK = {
    "fqdn": "otakunesia.example", "domain": "example",
    "interfaces": [{"name": "eth0", "mac": "52:54:00:12:34:56", "addrs": ["116.212.75.236/24"], "up": True}],
    "default_gateway": "116.212.75.1", "dns_servers": ["1.1.1.1"],
    "timezone": "Asia/Jakarta", "utc_offset": "+07:00",
    "sessions": [{"user": "root", "line": "pts/0", "from": "103.204.15.34"}],
}


def report(**extra):
    return {"agent_id": "x", "hostname": "blue-host", "hygiene_score": 65,
            "issues": [{"severity": "high", "category": "ssh", "message": "SSH allows root to log in with a password"}],
            "open_ports": [{"port": 22, "proto": "tcp", "state": "LISTEN", "addr": "0.0.0.0", "process": "sshd"}],
            **extra}


@pytest.fixture
async def hygiene_client(evidence_api):
    from fastapi import FastAPI

    from app.api.routes import hygiene
    from app.core.database import get_db

    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(hygiene.router)
    app.dependency_overrides[get_db] = database
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client, evidence_api


async def _stored(env):
    from app.models.models import HygieneSnapshot
    async with env.sessions() as db:
        return (await db.execute(select(HygieneSnapshot).order_by(HygieneSnapshot.collected_at))).scalars().all()


async def test_network_identity_is_kept_with_where_the_report_came_from(hygiene_client):
    client, env = hygiene_client
    r = await client.post("/api/hygiene", json=report(network=NETWORK),
                          headers={"X-Agent-Token": "blue-token", "X-Real-IP": "116.212.75.236"})
    assert r.status_code == 204, r.text
    snap = (await _stored(env))[-1]
    assert snap.network["fqdn"] == "otakunesia.example"
    assert snap.network["interfaces"][0]["addrs"] == ["116.212.75.236/24"]
    assert snap.network["sessions"][0]["from"] == "103.204.15.34"
    assert snap.network["seen_from"] == "116.212.75.236"
    assert snap.open_ports[0]["process"] == "sshd" and snap.open_ports[0]["addr"] == "0.0.0.0"


async def test_older_agents_without_network_still_record_where_from(hygiene_client):
    client, env = hygiene_client
    r = await client.post("/api/hygiene", json=report(), headers={"X-Agent-Token": "blue-token", "X-Real-IP": "10.0.0.9"})
    assert r.status_code == 204
    assert (await _stored(env))[-1].network == {"seen_from": "10.0.0.9"}


async def test_an_oversized_network_report_keeps_only_the_identity(hygiene_client):
    client, env = hygiene_client
    big = dict(NETWORK, sessions=[{"user": "u" * 200, "from": "x" * 200}] * 400)
    r = await client.post("/api/hygiene", json=report(network=big), headers={"X-Agent-Token": "blue-token"})
    assert r.status_code == 204
    net = (await _stored(env))[-1].network
    assert "sessions" not in net and net["fqdn"] == "otakunesia.example" and "seen_from" in net
