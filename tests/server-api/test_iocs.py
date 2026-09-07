from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.iocs import router as iocs_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import IocLink, IocObservation


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


def _observation(group_id: str = "blue", indicator: str = "1.2.3.4") -> IocObservation:
    return IocObservation(
        id=uuid4(), group_id=group_id, indicator=indicator, ioc_type="ipv4",
        confidence=0.9, verdict="malicious", source="ti_enrichment",
        first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc),
    )


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def all(self):
        return self._value


class _FakeSession:
    def __init__(self, results: list) -> None:
        self._results = list(results)

    async def execute(self, *_args, **_kwargs):
        return self._results.pop(0)


def _client(current_user, db_session: _FakeSession, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(iocs_router)

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_pivot_returns_observations_and_links_for_own_tenant() -> None:
    analyst = _make_user("analyst", ["iocs:read"])
    obs = _observation()
    link = IocLink(
        id=uuid4(), ioc_id=obs.id, group_id="blue", entity_type="alert",
        entity_id="alert-1", linked_at=datetime.now(timezone.utc),
    )
    session = _FakeSession([_FakeResult([obs]), _FakeResult([link])])
    client = _client(analyst, session)

    response = client.get("/api/iocs/1.2.3.4")

    assert response.status_code == 200
    body = response.json()
    assert body["observations"][0]["indicator"] == "1.2.3.4"
    assert body["observations"][0]["verdict"] == "malicious"
    assert body["links"][0]["entity_type"] == "alert"
    assert body["links"][0]["entity_id"] == "alert-1"


def test_pivot_returns_404_when_indicator_not_found_in_tenant() -> None:
    analyst = _make_user("analyst", ["iocs:read"])
    session = _FakeSession([_FakeResult([])])
    client = _client(analyst, session)

    response = client.get("/api/iocs/9.9.9.9")

    assert response.status_code == 404


def test_superadmin_without_group_id_query_param_gets_422() -> None:
    superadmin = _make_user("superadmin", [])
    session = _FakeSession([])
    client = _client(superadmin, session, group_id=None)

    response = client.get("/api/iocs/1.2.3.4")

    assert response.status_code == 422


def test_superadmin_can_view_a_specific_tenant_via_query_param() -> None:
    superadmin = _make_user("superadmin", [])
    obs = _observation(group_id="red")
    session = _FakeSession([_FakeResult([obs]), _FakeResult([])])
    client = _client(superadmin, session, group_id=None)

    response = client.get("/api/iocs/1.2.3.4?group_id=red")

    assert response.status_code == 200
    assert response.json()["observations"][0]["verdict"] == "malicious"


def test_caller_without_permission_is_rejected() -> None:
    viewer = _make_user("viewer", [])
    session = _FakeSession([])
    client = _client(viewer, session)

    response = client.get("/api/iocs/1.2.3.4")

    assert response.status_code == 403
