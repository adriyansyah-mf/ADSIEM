from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.cases import router as cases_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.services.custody_export import verify_bundle

NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def _stub_audit_log():
    with patch("app.api.routes.cases.audit_log", new=AsyncMock()):
        yield


pytestmark = pytest.mark.usefixtures("_stub_audit_log")


def _case(alert_id=None, created_at=NOW, group_id="blue"):
    return SimpleNamespace(
        id=uuid4(), alert_id=alert_id, created_at=created_at, group_id=group_id,
        title="Brute force case", description="desc", severity="high", status="open",
    )


def _alert(**kwargs):
    defaults = dict(
        id=uuid4(), created_at=NOW, title="Suspicious login", severity="high", status="new",
        source_ip="10.0.0.5", hostname="host-1", mitre_techniques=[], kill_chain_stage=None,
        correlation_id=None, correlation_key=None, source_event_ids=[], agent_id=uuid4(),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _ScalarsResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return self

    def all(self):
        return self._values


class _RowsResult:
    def __init__(self, values):
        self._values = values

    def all(self):
        return self._values


class _FakeSession:
    def __init__(self, *, case, triggering=None, related_alerts=None, full_alerts=None):
        self._case = case
        self._triggering = triggering
        self._related_alerts = related_alerts or []
        self._full_alerts = full_alerts if full_alerts is not None else (related_alerts or [])

    async def get(self, model, id_):
        return self._triggering

    async def execute(self, stmt, *args, **kwargs):
        sql = str(stmt)
        if "FROM cases" in sql:
            return _ScalarResult(self._case)
        if "alerts.id IN" in sql:
            return _ScalarsResult(self._full_alerts)
        if "FROM ioc_links" in sql:
            return _RowsResult([])
        if "FROM soar_run_steps" in sql:
            return _ScalarsResult([])
        if "FROM fim_events" in sql:
            return _ScalarsResult([])
        if "FROM case_notes" in sql:
            return _ScalarsResult([])
        if "FROM alert_notes" in sql:
            return _ScalarsResult([])
        if "FROM alerts" in sql:
            return _ScalarsResult(self._related_alerts)
        raise AssertionError(f"unexpected query: {sql[:200]}")


def _client(session: _FakeSession, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(cases_router)

    async def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=uuid4())
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_export_returns_404_for_missing_case():
    session = _FakeSession(case=None)
    client = _client(session)

    response = client.get(f"/api/cases/{uuid4()}/export")

    assert response.status_code == 404


def test_export_bundle_is_internally_valid():
    case_id = uuid4()
    alert_id = uuid4()
    case = _case(alert_id=alert_id)
    case.id = case_id
    triggering = _alert(id=alert_id)
    session = _FakeSession(case=case, triggering=triggering, related_alerts=[triggering])
    client = _client(session)

    response = client.get(f"/api/cases/{case_id}/export")

    assert response.status_code == 200
    body = response.json()
    assert body["algorithm"] == "HMAC-SHA256"
    assert body["export"]["sections"]["case"]["id"] == str(case_id)
    assert len(body["export"]["sections"]["alerts"]) == 1

    result = verify_bundle(body["export"], body["signature"])
    assert result["valid"] is True


def test_export_signature_fails_verification_if_tampered():
    case = _case()
    session = _FakeSession(case=case)
    client = _client(session)

    body = client.get(f"/api/cases/{case.id}/export").json()
    body["export"]["sections"]["case"]["severity"] = "low"

    result = verify_bundle(body["export"], body["signature"])
    assert result["valid"] is False
