from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.sla_policies import (
    DEFAULT_BREACH_MINUTES,
    DEFAULT_WARN_MINUTES,
    SEVERITIES,
    router as sla_router,
)
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import SlaPolicy

pytestmark = pytest.mark.usefixtures("_stub_audit_log")


@pytest.fixture
def _stub_audit_log():
    with patch("app.api.routes.sla_policies.audit_log", new=AsyncMock()):
        yield


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        return self

    def all(self):
        return self._value


class _FakeSession:
    def __init__(self, execute_result=None):
        self.added: list = []
        self.committed = 0
        self._execute_result = execute_result

    def add(self, instance) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.committed += 1

    async def execute(self, *_args, **_kwargs):
        return self._execute_result


def _client(current_user, db_session: _FakeSession, group_id: str = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(sla_router)

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_list_returns_platform_defaults_when_no_override_exists() -> None:
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession(execute_result=_FakeResult([]))
    client = _client(admin, session)

    response = client.get("/api/sla-policies")

    assert response.status_code == 200
    body = {p["severity"]: p for p in response.json()}
    assert set(body) == set(SEVERITIES)
    assert body["critical"]["warn_minutes"] == DEFAULT_WARN_MINUTES["critical"]
    assert body["critical"]["breach_minutes"] == DEFAULT_BREACH_MINUTES["critical"]
    assert all(p["is_default"] for p in body.values())


def test_list_prefers_tenant_override_over_default() -> None:
    admin = _make_user("admin", ["settings:manage"], group_id="blue")
    override = SlaPolicy(id=uuid4(), group_id="blue", severity="high", warn_minutes=5, breach_minutes=10)
    session = _FakeSession(execute_result=_FakeResult([override]))
    client = _client(admin, session)

    response = client.get("/api/sla-policies")

    body = {p["severity"]: p for p in response.json()}
    assert body["high"]["warn_minutes"] == 5
    assert body["high"]["breach_minutes"] == 10
    assert body["high"]["is_default"] is False
    assert body["low"]["is_default"] is True  # untouched severities stay default


def test_upsert_rejects_warn_greater_than_or_equal_breach() -> None:
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession(execute_result=_FakeResult(None))
    client = _client(admin, session)

    response = client.put("/api/sla-policies/high", json={"warn_minutes": 60, "breach_minutes": 60})

    assert response.status_code == 422
    assert session.added == []


def test_upsert_rejects_unknown_severity() -> None:
    admin = _make_user("admin", ["settings:manage"])
    session = _FakeSession()
    client = _client(admin, session)

    response = client.put("/api/sla-policies/urgent", json={"warn_minutes": 5, "breach_minutes": 10})

    assert response.status_code == 422


def test_upsert_creates_new_override_when_none_exists() -> None:
    admin = _make_user("admin", ["settings:manage"], group_id="blue")
    session = _FakeSession(execute_result=_FakeResult(None))
    client = _client(admin, session)

    response = client.put("/api/sla-policies/high", json={"warn_minutes": 30, "breach_minutes": 45})

    assert response.status_code == 200
    assert len(session.added) == 1
    created = session.added[0]
    assert created.group_id == "blue"
    assert created.severity == "high"
    assert created.warn_minutes == 30


def test_upsert_updates_existing_override_in_place() -> None:
    admin = _make_user("admin", ["settings:manage"], group_id="blue")
    existing = SlaPolicy(id=uuid4(), group_id="blue", severity="high", warn_minutes=10, breach_minutes=20)
    session = _FakeSession(execute_result=_FakeResult(existing))
    client = _client(admin, session)

    response = client.put("/api/sla-policies/high", json={"warn_minutes": 15, "breach_minutes": 25})

    assert response.status_code == 200
    assert session.added == []  # updated in place, not a new row
    assert existing.warn_minutes == 15
    assert existing.breach_minutes == 25


def test_caller_without_permission_is_rejected() -> None:
    viewer = _make_user("viewer", ["logs:read"])
    session = _FakeSession()
    client = _client(viewer, session)

    response = client.get("/api/sla-policies")

    assert response.status_code == 403
