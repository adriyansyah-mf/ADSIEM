from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.investigation import router as investigation_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group


def _make_user(group_id: str = "blue"):
    return SimpleNamespace(id=uuid4(), group_id=group_id)


def _saved_query(owner_id, **kwargs):
    defaults = dict(
        id=uuid4(), group_id="blue", owner_id=owner_id, name="q", query_type="alerts",
        query_params={}, is_shared=False, created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _bookmark(owner_id, **kwargs):
    defaults = dict(
        id=uuid4(), group_id="blue", owner_id=owner_id, entity_type="alert", entity_id="a1",
        note=None, is_shared=False, created_at=datetime.now(timezone.utc),
    )
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
    def __init__(self, results: list | None = None) -> None:
        self._results = list(results or [])
        self.added: list = []
        self.deleted: list = []
        self.commits = 0

    async def execute(self, *_args, **_kwargs):
        return self._results.pop(0)

    def add(self, instance) -> None:
        self.added.append(instance)

    async def delete(self, instance) -> None:
        self.deleted.append(instance)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, instance) -> None:
        pass


def _client(current_user, db_session: _FakeSession, group_id: str | None = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(investigation_router)

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    return TestClient(app)


# -- saved queries --

def test_list_saved_queries_scopes_to_own_and_shared():
    user = _make_user()
    mine = _saved_query(user.id, name="mine")
    session = _FakeSession([_FakeResult([mine])])
    client = _client(user, session)

    response = client.get("/api/saved-queries")

    assert response.status_code == 200
    assert response.json()[0]["name"] == "mine"


def test_create_saved_query_rejects_unknown_query_type():
    user = _make_user()
    session = _FakeSession()
    client = _client(user, session)

    response = client.post("/api/saved-queries", json={"name": "x", "query_type": "bogus"})

    assert response.status_code == 422


def test_create_saved_query_succeeds():
    user = _make_user()
    session = _FakeSession()
    client = _client(user, session)

    response = client.post(
        "/api/saved-queries",
        json={"name": "Failed logins", "query_type": "alerts", "query_params": {"severity": "high"}},
    )

    assert response.status_code == 201
    assert response.json()["name"] == "Failed logins"
    assert len(session.added) == 1


def test_delete_saved_query_rejects_non_owner():
    user = _make_user()
    other_owner_query = _saved_query(uuid4())
    session = _FakeSession([_FakeResult(other_owner_query)])
    client = _client(user, session)

    response = client.delete(f"/api/saved-queries/{other_owner_query.id}")

    assert response.status_code == 404
    assert session.deleted == []


def test_delete_saved_query_succeeds_for_owner():
    user = _make_user()
    mine = _saved_query(user.id)
    session = _FakeSession([_FakeResult(mine)])
    client = _client(user, session)

    response = client.delete(f"/api/saved-queries/{mine.id}")

    assert response.status_code == 204
    assert session.deleted == [mine]


# -- bookmarks --

def test_create_bookmark_rejects_unknown_entity_type():
    user = _make_user()
    session = _FakeSession()
    client = _client(user, session)

    response = client.post("/api/bookmarks", json={"entity_type": "widget", "entity_id": "x"})

    assert response.status_code == 422


def test_create_bookmark_upserts_existing_for_same_owner_and_entity():
    user = _make_user()
    existing = _bookmark(user.id, entity_id="alert-1", note="old")
    session = _FakeSession([_FakeResult(existing)])
    client = _client(user, session)

    response = client.post(
        "/api/bookmarks", json={"entity_type": "alert", "entity_id": "alert-1", "note": "updated"},
    )

    assert response.status_code == 201
    assert response.json()["note"] == "updated"
    assert session.added == []  # updated in place, not a new row
    assert session.commits == 1


def test_create_bookmark_inserts_new_when_none_exists():
    user = _make_user()
    session = _FakeSession([_FakeResult(None)])
    client = _client(user, session)

    response = client.post("/api/bookmarks", json={"entity_type": "case", "entity_id": "case-1"})

    assert response.status_code == 201
    assert len(session.added) == 1


def test_delete_bookmark_rejects_non_owner():
    user = _make_user()
    other = _bookmark(uuid4())
    session = _FakeSession([_FakeResult(other)])
    client = _client(user, session)

    response = client.delete(f"/api/bookmarks/{other.id}")

    assert response.status_code == 404


def test_list_bookmarks_filters_by_entity_type():
    user = _make_user()
    bm = _bookmark(user.id, entity_type="indicator", entity_id="1.2.3.4")
    session = _FakeSession([_FakeResult([bm])])
    client = _client(user, session)

    response = client.get("/api/bookmarks?entity_type=indicator")

    assert response.status_code == 200
    assert response.json()[0]["entity_type"] == "indicator"
