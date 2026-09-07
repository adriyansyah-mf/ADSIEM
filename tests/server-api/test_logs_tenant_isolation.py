from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.logs import MAX_PAGE_SIZE, router as logs_router
from app.core.deps import get_current_user, get_scoped_group


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


def _client(current_user, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(logs_router)
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_tenant_scoped_caller_gets_group_id_filter_applied_to_es_query():
    """Regression test: list_logs previously built its ES query with no
    group_id filter at all, so any authenticated caller with logs:read could
    read every tenant's raw logs. It must filter by the caller's own tenant,
    exactly like the sibling /api/events route already does."""
    analyst = _make_user("analyst", ["logs:read"], group_id="blue")
    client = _client(analyst)

    with patch("app.api.routes.logs.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get("/api/logs")

    assert response.status_code == 200
    query = mock_search.call_args.args[0]
    assert {"term": {"group_id": "blue"}} in query["bool"]["filter"]


def test_superadmin_with_no_scoped_group_gets_unfiltered_query():
    superadmin = _make_user("superadmin", [])
    client = _client(superadmin, group_id=None)

    with patch("app.api.routes.logs.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get("/api/logs")

    assert response.status_code == 200
    query = mock_search.call_args.args[0]
    assert query == {"match_all": {}}


def test_page_size_is_capped_server_side():
    analyst = _make_user("analyst", ["logs:read"])
    client = _client(analyst)

    with patch("app.api.routes.logs.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get(f"/api/logs?page_size={MAX_PAGE_SIZE * 10}")

    assert response.status_code == 422
    mock_search.assert_not_called()


def test_page_size_at_the_cap_is_accepted():
    analyst = _make_user("analyst", ["logs:read"])
    client = _client(analyst)

    with patch("app.api.routes.logs.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get(f"/api/logs?page_size={MAX_PAGE_SIZE}")

    assert response.status_code == 200
    mock_search.assert_called_once()
