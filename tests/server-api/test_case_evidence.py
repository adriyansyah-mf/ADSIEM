"""Case evidence and remediation through HTTP over an isolated PostgreSQL schema."""
import os
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.routes.cases import router
from app.core.database import Base, get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentTask, Alert, Case, CaseAlert, Role, User


async def test_evidence_includes_primary_and_multiple_linked_indicators(case_env):
    env = case_env
    response = await env.client.get(f"/api/cases/{env.case.id}/evidence")
    assert response.status_code == 200
    assert response.json()["blockable_ips"] == ["8.8.8.1", "8.8.8.2"]
    assert {a["id"] for a in response.json()["alerts"]} == {str(a.id) for a in env.alerts[:2]}


async def test_case_list_and_timeline_use_all_linked_alerts(case_env):
    env = case_env
    response = await env.client.get("/api/cases", params={"alert_id": str(env.alerts[1].id), "hostname": "host1"})
    assert response.status_code == 200
    assert response.json()["items"][0]["alert_count"] == 2
    timeline = await env.client.get(f"/api/cases/{env.case.id}/timeline")
    assert timeline.status_code == 200
    assert {i["id"] for i in timeline.json()["items"]} == {str(a.id) for a in env.alerts[:2]}


async def test_multi_host_remediation_retry_is_idempotent(case_env):
    env = case_env
    body = {"request_id": str(uuid4()), "agent_ids": [str(a.id) for a in env.agents[:2]],
            "ips": ["8.8.8.1", "8.8.8.2"], "duration_seconds": 3600}
    first = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    second = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    assert first.status_code == second.status_code == 201
    assert len(first.json()) == 4
    assert {t["id"] for t in first.json()} == {t["id"] for t in second.json()}
    assert {t["status"] for t in first.json()} == {"pending"}
    async with env.sessions() as db:
        assert len((await db.execute(select(AgentTask))).scalars().all()) == 4


async def test_case_block_lists_ips_until_duration_ends(case_env):
    from app.models.models import IPBlockEntry
    env = case_env
    body = {"request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)],
            "ips": ["8.8.8.1", "8.8.8.2"], "duration_seconds": 86400}
    assert (await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)).status_code == 201
    async with env.sessions() as db:
        rows = (await db.execute(select(IPBlockEntry).order_by(IPBlockEntry.cidr))).scalars().all()
    assert [(r.cidr, r.group_id, r.source, r.status) for r in rows] == [
        ("8.8.8.1/32", "blue", "manual", "active"), ("8.8.8.2/32", "blue", "manual", "active")]
    for r in rows:
        assert 86390 <= (r.expires_at - r.created_at).total_seconds() <= 86410


async def test_case_block_never_shortens_a_permanent_blocklist_entry(case_env):
    from app.models.models import IPBlockEntry
    env = case_env
    async with env.sessions() as db:
        db.add(IPBlockEntry(cidr="8.8.8.1/32", group_id="blue", source="manual", status="active", reason="analyst"))
        await db.commit()
    body = {"request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"],
            "duration_seconds": 3600}
    assert (await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)).status_code == 201
    async with env.sessions() as db:
        [row] = (await db.execute(select(IPBlockEntry))).scalars().all()
    assert row.status == "active" and row.expires_at is None


@pytest.mark.parametrize("invalid", ["foreign_agent", "unknown_ip", "invalid_ip", "invalid_duration"])
async def test_invalid_remediation_enqueues_nothing(case_env, invalid):
    env = case_env
    body = {"request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"], "duration_seconds": 3600}
    if invalid == "foreign_agent":
        body["agent_ids"] = [str(env.agents[2].id)]
    if invalid == "unknown_ip":
        body["ips"] = ["1.1.1.1"]
    if invalid == "invalid_ip":
        body["ips"] = ["example.com;whoami"]
    if invalid == "invalid_duration":
        body["duration_seconds"] = -1
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json=body)
    assert response.status_code == 422
    async with env.sessions() as db:
        assert (await db.execute(select(AgentTask))).scalars().all() == []


async def test_detach_keeps_alert_and_removes_it_from_remediation(case_env):
    env = case_env
    response = await env.client.put(f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}", json={"status": "detached"})
    assert response.status_code == 200
    evidence = (await env.client.get(f"/api/cases/{env.case.id}/evidence")).json()
    assert evidence["blockable_ips"] == ["8.8.8.1"]
    assert next(a for a in evidence["alerts"] if a["id"] == str(env.alerts[1].id))["status"] == "detached"
    async with env.sessions() as db:
        assert await db.get(Alert, env.alerts[1].id) is not None


@pytest.mark.parametrize("status", ["in_review", "escalated", "resolved", "closed"])
async def test_non_open_case_rejects_membership_changes(case_env, status):
    env = case_env
    async with env.sessions() as db:
        case = await db.get(Case, env.case.id)
        case.status = status
        await db.commit()
    response = await env.client.put(f"/api/cases/{env.case.id}/alerts/{env.alerts[1].id}", json={"status": "detached"})
    assert response.status_code == 409


async def test_other_group_cannot_read_case_or_queue_remediation(case_env):
    env = case_env
    env.user.group_id = "red"
    assert (await env.client.get(f"/api/cases/{env.case.id}/evidence")).status_code == 404
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json={
        "request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"],
    })
    assert response.status_code == 404


async def test_viewer_cannot_queue_remediation(case_env):
    env = case_env
    env.user.role = SimpleNamespace(name="viewer", permissions=[])
    response = await env.client.post(f"/api/cases/{env.case.id}/remediations", json={
        "request_id": str(uuid4()), "agent_ids": [str(env.agents[0].id)], "ips": ["8.8.8.1"],
    })
    assert response.status_code == 403


async def test_case_from_grouped_attack_links_every_alert(case_env, monkeypatch):
    from app.api.routes import cases as cases_route
    monkeypatch.setattr(cases_route, "audit_log", lambda *a, **k: None)
    env = case_env
    response = await env.client.post("/api/cases", json={
        "title": "Attack on host0", "severity": "high",
        "alert_id": str(env.alerts[0].id), "alert_ids": [str(env.alerts[0].id), str(env.alerts[1].id)],
    })
    assert response.status_code == 201
    assert sorted(response.json()["ioc_data"]["affected_hosts"]) == ["host0", "host1"]
    async with env.sessions() as db:
        links = (await db.execute(select(CaseAlert).where(CaseAlert.case_id == response.json()["id"]))).scalars().all()
    assert [(link.alert_id, link.method, link.status) for link in links] == [(env.alerts[1].id, "analyst", "linked")]


async def test_case_from_grouped_attack_rejects_alerts_of_another_group(case_env):
    env = case_env
    response = await env.client.post("/api/cases", json={
        "title": "Attack", "severity": "high", "alert_id": str(env.alerts[0].id), "alert_ids": [str(env.alerts[2].id)],
    })
    assert response.status_code == 404
    response = await env.client.post("/api/cases", json={"title": "Attack", "alert_ids": [str(env.alerts[1].id)]})
    assert response.status_code == 422
