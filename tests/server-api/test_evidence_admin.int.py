# tests/server-api/test_evidence_admin.int.py
"""Operators retry dead-lettered evidence: agents:manage only, scoped to the
group the receipt was accepted under, dead letters only, payload kept,
attempt state reset, audited."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4


def env_user(role, group, perms):
    return SimpleNamespace(id=uuid4(), group_id=group, username=role,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


async def dead_letter(env, group="blue", agent="blue", status="dead_letter", payload=True):
    from app.models import models
    async with env.sessions() as db:
        row = models.EvidenceInbox(
            agent_id=env.agents[agent], event_id=uuid4(), group_id=group, hostname=f"{agent}-host",
            payload_digest="0" * 64, payload=json.dumps({"raw_message": "x"}) if payload else None,
            payload_bytes=20, collected_at=datetime.now(timezone.utc), status=status, failure_count=20,
            last_error="RuntimeError: elasticsearch unavailable")
        db.add(row)
        await db.commit()
        return row.receipt_id


def manager(group="blue"):
    return env_user(role="admin", group=group, perms=("agents:read", "agents:manage"))


async def test_dead_letters_are_listed_with_metadata_only(evidence_api):
    receipt = await dead_letter(evidence_api)
    detail = (await evidence_api.client.get(f"/api/agents/{evidence_api.agents['blue']}/evidence")).json()
    assert detail["inbox"]["dead_letter"] == 1
    [row] = detail["inbox"]["dead_letters"]
    assert row["receipt_id"] == str(receipt) and row["failure_count"] == 20
    assert "payload" not in row and "raw_message" not in json.dumps(detail)


async def test_retry_resets_attempts_keeps_payload_and_audits(evidence_api):
    from app.models import models
    receipt = await dead_letter(evidence_api)
    evidence_api.user = manager()
    blue = evidence_api.agents["blue"]
    r = await evidence_api.client.post(f"/api/agents/{blue}/evidence/{receipt}/retry")
    assert r.status_code == 200, r.text
    async with evidence_api.sessions() as db:
        row = await db.get(models.EvidenceInbox, receipt)
        assert row.status == "pending" and row.failure_count == 0 and row.last_error is None
        assert json.loads(row.payload) == {"raw_message": "x"}
        assert row.next_attempt_at <= datetime.now(timezone.utc)
    [(actor, action, resource, detail)] = evidence_api.audits
    assert action == "evidence_retried" and resource == str(receipt) and detail["failure_count"] == 20
    # only dead letters
    r = await evidence_api.client.post(f"/api/agents/{blue}/evidence/{receipt}/retry")
    assert r.status_code == 409


async def test_analyst_cannot_retry(evidence_api):
    receipt = await dead_letter(evidence_api)
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['blue']}/evidence/{receipt}/retry")
    assert r.status_code == 403


async def test_retry_is_scoped_to_the_receipts_original_group(evidence_api):
    evidence_api.user = manager("blue")
    red_receipt = await dead_letter(evidence_api, group="red", agent="red")
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['red']}/evidence/{red_receipt}/retry")
    assert r.status_code == 404  # another group's agent
    # accepted while the blue agent was still in group "old": not blue's to retry
    moved = await dead_letter(evidence_api, group="old", agent="blue")
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['blue']}/evidence/{moved}/retry")
    assert r.status_code == 404
    detail = (await evidence_api.client.get(f"/api/agents/{evidence_api.agents['blue']}/evidence")).json()
    assert detail["inbox"]["dead_letter"] == 0
    # a receipt of another agent cannot be retried through this agent
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['blue']}/evidence/{red_receipt}/retry")
    assert r.status_code == 404
    evidence_api.user = env_user(role="superadmin", group="default", perms=())
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['blue']}/evidence/{moved}/retry")
    assert r.status_code == 200


async def test_released_payload_cannot_be_retried(evidence_api):
    receipt = await dead_letter(evidence_api, payload=False)
    evidence_api.user = manager()
    r = await evidence_api.client.post(f"/api/agents/{evidence_api.agents['blue']}/evidence/{receipt}/retry")
    assert r.status_code == 409
