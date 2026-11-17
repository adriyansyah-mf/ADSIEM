# tests/server-api/test_prevention_signer.int.py
"""Signer prevention rules (the Authenticode publisher, Windows agents) and
the built-in VPN pack: validated on input, seeded disabled, never
overwritten, and only enabled rules reach agents."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import prevention_rules
from app.core.database import get_db
from app.core.deps import get_current_user

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(prevention_rules.router)
    app.include_router(prevention_rules.agent_router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    prevention_rules.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        evidence_api.user = evidence_api.make_user(role="admin", perms=("rules:create", "rules:update", "rules:delete"))
        yield evidence_api


async def test_signer_rules_are_validated(api):
    c = api.api
    ok = await c.post("/api/prevention-rules", json={"name": "no psiphon", "rule_type": "signer",
                                                      "value": " Psiphon Inc. ", "action": "block"})
    assert ok.status_code == 201, ok.text
    assert ok.json()["value"] == "Psiphon Inc."
    # Microsoft signs Windows itself: never a block rule; a detect rule is fine
    ms = await c.post("/api/prevention-rules", json={"name": "ms", "rule_type": "signer",
                                                      "value": "Microsoft Windows", "action": "block"})
    assert ms.status_code == 422 and "Microsoft" in ms.text
    assert (await c.post("/api/prevention-rules", json={"name": "ms watch", "rule_type": "signer",
                                                        "value": "Microsoft Windows"})).status_code == 201
    for bad in ("", "x", "a\nb", "y" * 201):
        r = await c.post("/api/prevention-rules", json={"name": f"bad {len(bad)}", "rule_type": "signer", "value": bad})
        assert r.status_code == 422, bad


async def test_vpn_pack_is_seeded_off_and_never_overwritten(api):
    from app.services.prevention_pack import PACK_PREFIX, VPN_SIGNERS, seed_pack
    async with api.sessions() as db:
        assert await seed_pack(db) == len(VPN_SIGNERS)
    async with api.sessions() as db:
        assert await seed_pack(db) == 0  # idempotent
    rows = [r for r in (await api.api.get("/api/prevention-rules")).json() if r["name"].startswith(PACK_PREFIX)]
    assert len(rows) == len(VPN_SIGNERS)
    assert all(r["rule_type"] == "signer" and r["action"] == "block" and not r["is_enabled"] for r in rows)
    assert {r["value"] for r in rows} >= {"nordvpn s.a.", "Proton AG", "THE TOR PROJECT, INC."}
    # disabled rules never reach agents
    prevention_rules.invalidate()
    body = (await api.api.post("/api/ingest/prevention-rules", json={}, headers=BLUE)).json()
    assert not any(r["name"].startswith(PACK_PREFIX) for r in body["rules"])
    # an analyst's toggle survives the next start
    nord = next(r for r in rows if r["value"] == "nordvpn s.a.")
    assert (await api.api.patch(f"/api/prevention-rules/{nord['id']}/toggle")).json()["is_enabled"] is True
    async with api.sessions() as db:
        await seed_pack(db)
    again = {r["id"]: r for r in (await api.api.get("/api/prevention-rules")).json()}
    assert again[nord["id"]]["is_enabled"] is True
    prevention_rules.invalidate()
    body = (await api.api.post("/api/ingest/prevention-rules", json={}, headers=BLUE)).json()
    assert [(r["rule_type"], r["value"]) for r in body["rules"] if r["name"].startswith(PACK_PREFIX)] == \
        [("signer", "nordvpn s.a.")]
