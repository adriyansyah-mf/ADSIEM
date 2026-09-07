from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.retention_policies import router as retention_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import RetentionPolicy

pytestmark = pytest.mark.usefixtures("_stub_audit_log")


@pytest.fixture
def _stub_audit_log():
    with patch("app.api.routes.retention_policies.audit_log", new=AsyncMock()):
        yield


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


def _setting(key: str, value: str):
    return SimpleNamespace(key=key, value=value)


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    def __init__(self, results: list) -> None:
        self._results = list(results)
        self.added: list = []
        self.committed = 0

    async def execute(self, *_a, **_kw):
        return self._results.pop(0)

    def add(self, instance) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.committed += 1


def _client(current_user, session: _FakeSession, group_id: str = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(retention_router)

    async def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_get_returns_platform_defaults_when_no_override_exists():
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession([
        _FakeResult(None),                       # no override row
        _FakeResult(_setting("retention_raw_logs_days", "30")),
        _FakeResult(_setting("retention_events_days", "90")),
        _FakeResult(_setting("retention_alerts_days", "180")),
    ])
    client = _client(admin, session)

    response = client.get("/api/retention-policies")

    assert response.status_code == 200
    body = response.json()
    assert body["log_retention_days"] == 90  # max(30, 90)
    assert body["alert_retention_days"] == 180
    assert body["is_override"] is False


def test_get_prefers_tenant_override_for_set_fields_only():
    admin = _make_user("admin", ["settings:manage"])
    override = RetentionPolicy(
        group_id="blue", log_retention_days=7, alert_retention_days=None, storage_quota_docs=5000,
    )
    session = _FakeSession([
        _FakeResult(override),
        _FakeResult(_setting("retention_raw_logs_days", "30")),
        _FakeResult(_setting("retention_events_days", "90")),
        _FakeResult(_setting("retention_alerts_days", "180")),
    ])
    client = _client(admin, session)

    response = client.get("/api/retention-policies")

    body = response.json()
    assert body["log_retention_days"] == 7          # overridden
    assert body["alert_retention_days"] == 180       # inherited default
    assert body["storage_quota_docs"] == 5000
    assert body["is_override"] is True


def test_upsert_creates_new_override_when_none_exists():
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession([
        _FakeResult(None),  # existing check in PUT
        _FakeResult(None),  # override lookup inside _effective_policy after commit
        _FakeResult(_setting("retention_raw_logs_days", "30")),
        _FakeResult(_setting("retention_events_days", "90")),
        _FakeResult(_setting("retention_alerts_days", "180")),
    ])
    client = _client(admin, session)

    response = client.put(
        "/api/retention-policies",
        json={"log_retention_days": 14, "alert_retention_days": None, "storage_quota_docs": 10000},
    )

    assert response.status_code == 200
    assert len(session.added) == 1
    assert session.added[0].log_retention_days == 14
    assert session.added[0].storage_quota_docs == 10000


def test_upsert_updates_existing_override_in_place():
    admin = _make_user("admin", ["settings:manage"])
    existing = RetentionPolicy(group_id="blue", log_retention_days=7, alert_retention_days=30, storage_quota_docs=None)
    session = _FakeSession([
        _FakeResult(existing),
        _FakeResult(existing),
        _FakeResult(_setting("retention_raw_logs_days", "30")),
        _FakeResult(_setting("retention_events_days", "90")),
        _FakeResult(_setting("retention_alerts_days", "180")),
    ])
    client = _client(admin, session)

    response = client.put("/api/retention-policies", json={"log_retention_days": 3})

    assert response.status_code == 200
    assert session.added == []
    assert existing.log_retention_days == 3
    assert existing.alert_retention_days is None  # explicitly cleared, not left at 30


def test_zero_is_a_valid_explicit_override_not_rejected():
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession([
        _FakeResult(None),
        _FakeResult(None),
        _FakeResult(_setting("retention_raw_logs_days", "30")),
        _FakeResult(_setting("retention_events_days", "90")),
        _FakeResult(_setting("retention_alerts_days", "180")),
    ])
    client = _client(admin, session)

    response = client.put("/api/retention-policies", json={"log_retention_days": 0})

    assert response.status_code == 200
    assert session.added[0].log_retention_days == 0


def test_negative_value_is_rejected():
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession([])
    client = _client(admin, session)

    response = client.put("/api/retention-policies", json={"log_retention_days": -1})

    assert response.status_code == 422


def test_superadmin_without_group_id_gets_422():
    superadmin = _make_user("superadmin", [])
    session = _FakeSession([])
    client = _client(superadmin, session, group_id=None)

    response = client.get("/api/retention-policies")

    assert response.status_code == 422


def test_caller_without_permission_is_rejected():
    viewer = _make_user("viewer", [])
    session = _FakeSession([])
    client = _client(viewer, session)

    response = client.get("/api/retention-policies")

    assert response.status_code == 403


def test_usage_reports_doc_count_and_over_quota_flag():
    admin = _make_user("admin", ["settings:manage"])
    policy = RetentionPolicy(group_id="blue", storage_quota_docs=100)
    session = _FakeSession([_FakeResult(policy)])
    client = _client(admin, session)

    with patch("app.api.routes.retention_policies.count_by_query", new=AsyncMock(return_value=150)):
        response = client.get("/api/retention-policies/usage")

    assert response.status_code == 200
    body = response.json()
    assert body["log_doc_count"] == 150
    assert body["storage_quota_docs"] == 100
    assert body["over_quota"] is True


def test_usage_not_over_quota_when_under_limit():
    admin = _make_user("admin", ["settings:manage"])
    policy = RetentionPolicy(group_id="blue", storage_quota_docs=1000)
    session = _FakeSession([_FakeResult(policy)])
    client = _client(admin, session)

    with patch("app.api.routes.retention_policies.count_by_query", new=AsyncMock(return_value=10)):
        response = client.get("/api/retention-policies/usage")

    assert response.json()["over_quota"] is False
