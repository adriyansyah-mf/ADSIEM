from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from app.api.routes.api_keys import RateLimitCreate, router as api_keys_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.core.security import hash_password
from app.models.models import ApiKey
from app.services.api_keys import (
    PermissionEscalationError,
    authenticate_api_key,
    create_api_key,
    generate_api_key,
    validate_requested_permissions,
)


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    permission_objs = [SimpleNamespace(name=p) for p in perms]
    role = SimpleNamespace(name=role_name, permissions=permission_objs)
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
    def __init__(self, execute_result: _FakeResult | None = None):
        self.added: list = []
        self.committed = 0
        self._execute_result = execute_result

    def add(self, instance) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.committed += 1

    async def refresh(self, instance) -> None:
        return None

    async def execute(self, *_args, **_kwargs):
        return self._execute_result


def _client(current_user, db_session: _FakeSession, group_id: str = "blue") -> TestClient:
    app = FastAPI()
    app.include_router(api_keys_router)

    async def override_db() -> AsyncIterator[_FakeSession]:
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    # This file exercises API-key CRUD logic, not rate limiting (that has its
    # own dedicated coverage in test_security_boundaries.py) — bypass it here
    # so repeated CI/local runs within the same real Redis window can't make
    # these tests flake once the group's api_key_creation budget is spent.
    app.dependency_overrides[RateLimitCreate] = lambda: None
    return TestClient(app)


# ── generate_api_key ─────────────────────────────────────────────


def test_generate_api_key_has_adsiem_prefix_and_dot_separated_secret() -> None:
    # When
    full_key, prefix, secret = generate_api_key()

    # Then
    assert prefix.startswith("adsiem_")
    assert full_key == f"{prefix}.{secret}"
    assert secret not in prefix


# ── create_api_key: Argon2 hash, never plaintext ─────────────────


@pytest.mark.asyncio
async def test_create_api_key_stores_argon2_hash_not_plaintext() -> None:
    # Given
    session = _FakeSession()

    # When
    api_key, full_key = await create_api_key(
        session,
        name="ci-bot",
        permissions=["alerts:read"],
        group_id="blue",
        expires_at=None,
        created_by=uuid4(),
    )

    # Then
    assert api_key in session.added
    assert api_key.secret_hash != full_key
    assert api_key.secret_hash.startswith("$argon2")
    secret = full_key.split(".", 1)[1]
    assert secret not in api_key.secret_hash


# ── validate_requested_permissions: escalation rejected ──────────


def test_permission_escalation_is_rejected_for_non_superadmin() -> None:
    with pytest.raises(PermissionEscalationError):
        validate_requested_permissions(
            {"users:manage"}, {"alerts:read"}, caller_is_superadmin=False
        )


def test_superadmin_may_grant_any_permission() -> None:
    validate_requested_permissions({"users:manage"}, set(), caller_is_superadmin=True)


def test_subset_of_caller_permissions_is_allowed() -> None:
    validate_requested_permissions(
        {"alerts:read"}, {"alerts:read", "cases:manage"}, caller_is_superadmin=False
    )


# ── authenticate_api_key: malformed / unknown / revoked / expired / wrong secret ──


@pytest.mark.asyncio
async def test_authenticate_rejects_unknown_prefix() -> None:
    session = _FakeSession(execute_result=_FakeResult(None))
    result = await authenticate_api_key(session, "adsiem_unknownprefix.somesecret")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_rejects_malformed_token() -> None:
    session = _FakeSession()
    result = await authenticate_api_key(session, "not-an-api-key")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_rejects_revoked_key() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_aaaa1111", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"],
        revoked_at=datetime.now(timezone.utc),
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    result = await authenticate_api_key(session, "adsiem_aaaa1111.realsecret")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_rejects_expired_key() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_bbbb2222", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    result = await authenticate_api_key(session, "adsiem_bbbb2222.realsecret")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_rejects_wrong_secret() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_cccc3333", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"],
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    result = await authenticate_api_key(session, "adsiem_cccc3333.wrongsecret")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_accepts_valid_key_and_updates_last_used_at() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_dddd4444", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"], last_used_at=None,
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    result = await authenticate_api_key(session, "adsiem_dddd4444.realsecret")
    assert result is key
    assert key.last_used_at is not None
    assert session.committed >= 1


# ── get_current_user: accepts API keys alongside JWT ──────────────


@pytest.mark.asyncio
async def test_get_current_user_rejects_invalid_api_key() -> None:
    session = _FakeSession(execute_result=_FakeResult(None))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="adsiem_zzzz9999.nope")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials, session)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_revoked_api_key() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_iiii0000", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"],
        revoked_at=datetime.now(timezone.utc),
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="adsiem_iiii0000.realsecret")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials, session)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_resolves_service_principal_for_valid_api_key() -> None:
    key = ApiKey(
        id=uuid4(), prefix="adsiem_eeee5555", secret_hash=hash_password("realsecret"),
        name="k", group_id="blue", permissions=["alerts:read"],
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="adsiem_eeee5555.realsecret")

    principal = await get_current_user(credentials, session)

    assert principal.group_id == "blue"
    assert principal.role.name != "superadmin"
    assert {getattr(p, "name", p) for p in principal.role.permissions} == {"alerts:read"}


# ── Route level: create / list / revoke ───────────────────────────


def test_create_route_returns_secret_exactly_once_and_persists_hash() -> None:
    admin = _make_user("admin", ["api_keys:manage", "alerts:read"], group_id="blue")
    session = _FakeSession()
    client = _client(admin, session)

    response = client.post("/api/api-keys", json={"name": "ci-bot", "permissions": ["alerts:read"]})

    assert response.status_code == 201
    body = response.json()
    assert body["secret"].startswith("adsiem_")
    stored = session.added[0]
    assert stored.secret_hash != body["secret"]
    assert stored.group_id == "blue"


def test_create_route_rejects_permission_escalation() -> None:
    admin = _make_user("admin", ["api_keys:manage"], group_id="blue")
    session = _FakeSession()
    client = _client(admin, session)

    response = client.post("/api/api-keys", json={"name": "ci-bot", "permissions": ["users:manage"]})

    assert response.status_code == 403
    assert session.added == []


def test_list_route_never_returns_the_secret() -> None:
    admin = _make_user("admin", ["api_keys:manage"], group_id="blue")
    existing = ApiKey(
        id=uuid4(), prefix="adsiem_ffff6666", secret_hash="$argon2$fakehash",
        name="k", group_id="blue", permissions=["alerts:read"],
        created_at=datetime.now(timezone.utc),
    )
    session = _FakeSession(execute_result=_FakeResult([existing]))
    client = _client(admin, session)

    response = client.get("/api/api-keys")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert "secret" not in body[0]
    assert "secret_hash" not in body[0]
    assert body[0]["prefix"] == "adsiem_ffff6666"


def test_revoke_route_returns_404_for_foreign_group_key() -> None:
    admin = _make_user("admin", ["api_keys:manage"], group_id="blue")
    session = _FakeSession(execute_result=_FakeResult(None))
    client = _client(admin, session)

    response = client.delete(f"/api/api-keys/{uuid4()}")

    assert response.status_code == 404


def test_revoke_route_marks_key_revoked() -> None:
    admin = _make_user("admin", ["api_keys:manage"], group_id="blue")
    key = ApiKey(
        id=uuid4(), prefix="adsiem_hhhh8888", secret_hash="x",
        name="k", group_id="blue", permissions=[],
    )
    session = _FakeSession(execute_result=_FakeResult(key))
    client = _client(admin, session)

    response = client.delete(f"/api/api-keys/{key.id}")

    assert response.status_code == 204
    assert key.revoked_at is not None
