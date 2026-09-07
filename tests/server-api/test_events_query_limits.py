from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.events import MAX_PAGE_SIZE, router as events_router
from app.core.deps import get_current_user, get_scoped_group


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    role = SimpleNamespace(name=role_name, permissions=[SimpleNamespace(name=p) for p in perms])
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


def _client(current_user, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(events_router)
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


def test_page_size_over_cap_is_rejected():
    analyst = _make_user("analyst", ["logs:read"])
    client = _client(analyst)

    with patch("app.api.routes.events.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get(f"/api/events?page_size={MAX_PAGE_SIZE + 1}")

    assert response.status_code == 422
    mock_search.assert_not_called()


def test_page_size_at_cap_is_accepted():
    analyst = _make_user("analyst", ["logs:read"])
    client = _client(analyst)

    with patch("app.api.routes.events.es_search", new=AsyncMock(return_value=([], 0, None))) as mock_search:
        response = client.get(f"/api/events?page_size={MAX_PAGE_SIZE}")

    assert response.status_code == 200
    mock_search.assert_called_once()
