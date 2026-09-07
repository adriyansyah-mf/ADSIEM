from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.entities import router as entities_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


def _alert(**kwargs):
    defaults = dict(
        id=uuid4(), title="Brute force", severity="high", status="new",
        created_at=datetime.now(timezone.utc), source_ip="10.0.0.5", hostname="host-1",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _case(**kwargs):
    defaults = dict(id=uuid4(), title="Case", status="open", severity="high", created_at=datetime.now(timezone.utc))
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def all(self):
        return self._value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    def __init__(self, results: list) -> None:
        self._results = list(results)

    async def execute(self, *_args, **_kwargs):
        return self._results.pop(0)


def _client(current_user, db_session: _FakeSession, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(entities_router)

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_pivot_by_ip_returns_matching_alerts_and_cases():
    analyst = _make_user("analyst", ["logs:read"])
    alert = _alert(source_ip="203.0.113.9")
    case = _case()
    session = _FakeSession([
        _FakeResult([alert]),   # alerts
        _FakeResult([case]),    # cases
        _FakeResult(None),      # ueba score
        _FakeResult([]),        # anomalies
    ])
    client = _client(analyst, session)

    response = client.get("/api/entities/ip/203.0.113.9")

    assert response.status_code == 200
    body = response.json()
    assert body["alerts"][0]["source_ip"] == "203.0.113.9"
    assert body["cases"][0]["id"] == str(case.id)
    assert body["risk_score"] is None


def test_pivot_returns_ueba_data_for_entity_types_with_no_alert_column():
    analyst = _make_user("analyst", ["logs:read"])
    ueba_score = SimpleNamespace(risk_score=0.8, anomaly_count=3)
    session = _FakeSession([
        _FakeResult(ueba_score),  # ueba score (no alert column match_column is None -> no alert/case queries)
        _FakeResult([]),          # anomalies
    ])
    client = _client(analyst, session)

    response = client.get("/api/entities/user/alice")

    assert response.status_code == 200
    body = response.json()
    assert body["alerts"] == []
    assert body["risk_score"] == 0.8


def test_pivot_returns_404_when_nothing_found():
    analyst = _make_user("analyst", ["logs:read"])
    session = _FakeSession([
        _FakeResult([]),    # alerts
        _FakeResult(None),  # ueba score
        _FakeResult([]),    # anomalies
    ])
    client = _client(analyst, session)

    response = client.get("/api/entities/hostname/nowhere")

    assert response.status_code == 404


def test_superadmin_without_group_id_gets_422():
    superadmin = _make_user("superadmin", [])
    session = _FakeSession([])
    client = _client(superadmin, session, group_id=None)

    response = client.get("/api/entities/ip/1.2.3.4")

    assert response.status_code == 422


def test_caller_without_permission_is_rejected():
    viewer = _make_user("viewer", [])
    session = _FakeSession([])
    client = _client(viewer, session)

    response = client.get("/api/entities/ip/1.2.3.4")

    assert response.status_code == 403
