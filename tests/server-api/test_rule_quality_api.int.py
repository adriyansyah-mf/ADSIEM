"""Rule quality (routes/rule_quality.py) and suppression expiry
(routes/suppressions.py): per-rule alert volume and false-positive rate in the
caller's group, advice for noisy rules, suppression hits, and the level
override the worker applies."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import rule_quality as routes
from app.api.routes import suppressions
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, AlertSuppression, Rule


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    async def audit(*args, **kwargs):
        evidence_api.audits.append(args[2:])

    monkeypatch.setattr(routes, "audit_log", audit)
    evidence_api.user = evidence_api.make_user(perms=("logs:read", "rules:update", "alerts:read", "alerts:manage"))
    app = FastAPI()
    app.include_router(routes.router)
    app.include_router(suppressions.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _seed(env):
    """Blue: a noisy rule closed mostly as false positives, a quiet good one;
    red's alerts on the noisy rule must not count for blue."""
    now = datetime.now(timezone.utc)
    async with env.sessions() as db:
        noisy = Rule(title="Noisy login", content="title: Noisy login", level="medium", group_id="blue")
        good = Rule(title="Webshell", content="title: Webshell", level="high", group_id="blue")
        idle = Rule(title="Never fires", content="title: Never fires", level="low", group_id="blue")
        db.add_all([noisy, good, idle])
        await db.flush()
        alerts = [Alert(title="Noisy login", severity="medium", rule_id=noisy.id, group_id="blue",
                        status="false_positive" if i < 9 else "resolved" if i < 10 else "new",
                        duplicate_count=1, created_at=now - timedelta(hours=i)) for i in range(12)]
        alerts.append(Alert(title="Noisy login", severity="medium", rule_id=noisy.id, group_id="blue",
                            status="false_positive", created_at=now - timedelta(days=60)))  # outside 30 days
        alerts += [Alert(title="Noisy login", severity="medium", rule_id=noisy.id, group_id="red", status="new")
                   for _ in range(5)]
        alerts.append(Alert(title="Webshell", severity="high", rule_id=good.id, group_id="blue", status="resolved"))
        db.add_all(alerts)
        db.add(AlertSuppression(entity_type="rule_title", entity_value="Noisy login", group_id="blue",
                                hit_count=40, is_active=True))
        await db.commit()
        return noisy.id, good.id


async def test_quality_counts_alerts_and_fp_rate_in_the_callers_group(env):
    noisy, good = await _seed(env)
    r = await env.api.get("/api/rule-quality", params={"days": 30})
    assert r.status_code == 200, r.text
    out = r.json()
    assert (out["rules_enabled"], out["rules_alerting"], out["alerts"], out["false_positives"]) == (3, 2, 13, 9)
    first, second = out["items"]
    assert first["rule_id"] == str(noisy)  # the rule with advice comes first
    assert (first["alerts"], first["false_positives"], first["resolved"], first["untriaged"], first["duplicates"]) == \
        (12, 9, 1, 2, 12)
    assert first["fp_rate"] == 0.9 and first["suppressed_hits"] == 40
    assert any("false positives" in a for a in first["advice"])
    assert second["rule_id"] == str(good) and second["fp_rate"] == 0.0 and second["advice"] == []


async def test_the_level_override_is_validated_and_cleared(env):
    noisy, _ = await _seed(env)
    r = await env.api.put(f"/api/rule-quality/{noisy}/level", json={"level_override": "LOW"})
    assert r.status_code == 200, r.text
    assert r.json() == {"rule_id": str(noisy), "level": "medium", "level_override": "low"}
    assert ("rule_level_override", "rule", str(noisy)) == env.audits[-1][:3]
    listed = (await env.api.get("/api/rule-quality")).json()["items"][0]
    assert listed["level_override"] == "low"
    # the rule's own level, or null, clears it
    assert (await env.api.put(f"/api/rule-quality/{noisy}/level", json={"level_override": "medium"})).json()[
        "level_override"] is None
    assert (await env.api.put(f"/api/rule-quality/{noisy}/level", json={"level_override": "urgent"})).status_code == 422
    env.user = env.make_user(perms=("logs:read",))
    assert (await env.api.put(f"/api/rule-quality/{noisy}/level", json={"level_override": "low"})).status_code == 403


async def test_another_groups_rule_cannot_be_overridden(env):
    async with env.sessions() as db:
        red = Rule(title="Red only", content="title: Red only", level="low", group_id="red")
        db.add(red)
        await db.commit()
    r = await env.api.put(f"/api/rule-quality/{red.id}/level", json={"level_override": "high"})
    assert r.status_code == 404


async def test_a_suppression_can_end_by_itself(env):
    body = {"entity_type": "hostname", "entity_value": "build-01", "reason": "patch window", "expires_in_days": 2}
    first = await env.api.post("/api/suppressions", json=body)
    assert first.status_code == 201, first.text
    out = first.json()
    ends = datetime.fromisoformat(out["expires_at"])
    assert timedelta(days=1, hours=23) < ends - datetime.now(timezone.utc) <= timedelta(days=2)
    assert out["hit_count"] == 0 and out["last_hit_at"] is None
    # asked again for longer: the same row is extended
    again = (await env.api.post("/api/suppressions", json={**body, "expires_in_days": 7})).json()
    assert again["id"] == out["id"] and datetime.fromisoformat(again["expires_at"]) > ends
    # asked again without an end: kept for good
    forever = (await env.api.post("/api/suppressions", json={k: v for k, v in body.items() if k != "expires_in_days"})).json()
    assert forever["id"] == out["id"] and forever["expires_at"] is None
    async with env.sessions() as db:
        assert len((await db.execute(select(AlertSuppression))).scalars().all()) == 1
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    r = await env.api.post("/api/suppressions", json={"entity_type": "ip", "entity_value": "10.9.9.9", "expires_at": past})
    assert r.status_code == 422
