from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.queues import router as queues_router
from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import WebhookDelivery

# These tests exercise retry/discard/metrics LOGIC, not audit logging (which
# has its own dedicated coverage in test_audit_chain.py). audit_log() always
# opens a real AsyncSessionLocal (by design, so it survives the request
# session closing) -- under TestClient's per-test pytest-asyncio event loop,
# a real engine connection opened in one test and reused in another collides
# ("attached to a different loop"), so it's stubbed out here.
pytestmark = pytest.mark.usefixtures("_stub_audit_log")


@pytest.fixture
def _stub_audit_log():
    with patch("app.api.routes.queues.audit_log", new=AsyncMock()):
        yield


@pytest.fixture(autouse=True)
def _stub_audit_log():
    with patch("app.api.routes.queues.audit_log", new=AsyncMock()):
        yield


def _make_user(role_name: str, perms: list[str], group_id: str = "blue"):
    permission_objs = [SimpleNamespace(name=p) for p in perms]
    role = SimpleNamespace(name=role_name, permissions=permission_objs)
    return SimpleNamespace(id=uuid4(), role=role, group_id=group_id)


class _FakeRedis:
    def __init__(self, lengths: dict[str, int] | None = None):
        self._lengths = lengths or {}

    async def xlen(self, key: str) -> int:
        return self._lengths.get(key, 0)

    async def xrange(self, key: str, count: int = 1):
        if self._lengths.get(key, 0) == 0:
            return []
        return [(f"{1000000}-0", {"dummy": "1"})]


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
        self.committed = 0
        self._execute_result = execute_result

    async def commit(self) -> None:
        self.committed += 1

    async def refresh(self, instance) -> None:
        return None

    async def execute(self, *_args, **_kwargs):
        return self._execute_result


def _client(current_user, db_session: _FakeSession, group_id: str = "blue", redis=None) -> TestClient:
    app = FastAPI()
    app.include_router(queues_router)

    async def override_db() -> AsyncIterator[_FakeSession]:
        yield db_session

    async def override_redis():
        return redis or _FakeRedis()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_scoped_group] = lambda: group_id
    if redis is not None:
        import app.api.routes.queues as queues_module
        queues_module.get_redis = override_redis
    return TestClient(app)


def _delivery(**overrides) -> WebhookDelivery:
    defaults = dict(
        id=uuid4(), alert_id=uuid4(), webhook_config_id=uuid4(), group_id="blue",
        payload={}, status="failed", attempts=5, last_error="Connection refused",
        error_class="ConnectError", first_failed_at=datetime.now(timezone.utc) - timedelta(hours=2),
        last_attempted_at=datetime.now(timezone.utc), created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    defaults.update(overrides)
    return WebhookDelivery(**defaults)


def test_list_webhook_deliveries_returns_typed_dlq_fields() -> None:
    admin = _make_user("admin", ["queues:manage"])
    delivery = _delivery()
    session = _FakeSession(execute_result=_FakeResult([delivery]))
    client = _client(admin, session)

    response = client.get("/api/queues/webhook-deliveries?status=failed")

    assert response.status_code == 200
    body = response.json()[0]
    assert body["status"] == "failed"
    assert body["attempts"] == 5
    assert body["last_error"] == "Connection refused"
    assert body["error_class"] == "ConnectError"
    assert body["first_failed_at"] is not None


def test_retry_resets_attempts_and_status() -> None:
    admin = _make_user("admin", ["queues:manage"])
    delivery = _delivery(status="failed", attempts=5)
    session = _FakeSession(execute_result=_FakeResult(delivery))
    client = _client(admin, session)

    response = client.post(f"/api/queues/webhook-deliveries/{delivery.id}/retry")

    assert response.status_code == 200
    assert delivery.status == "pending"
    assert delivery.attempts == 0


def test_discard_marks_delivery_discarded() -> None:
    admin = _make_user("admin", ["queues:manage"])
    delivery = _delivery(status="failed")
    session = _FakeSession(execute_result=_FakeResult(delivery))
    client = _client(admin, session)

    response = client.post(f"/api/queues/webhook-deliveries/{delivery.id}/discard")

    assert response.status_code == 200
    assert delivery.status == "discarded"


def test_retry_returns_404_for_foreign_tenant_delivery() -> None:
    admin = _make_user("admin", ["queues:manage"], group_id="blue")
    session = _FakeSession(execute_result=_FakeResult(None))  # scoped query finds nothing
    client = _client(admin, session)

    response = client.post(f"/api/queues/webhook-deliveries/{uuid4()}/retry")

    assert response.status_code == 404


def test_caller_without_permission_is_rejected() -> None:
    viewer = _make_user("viewer", ["logs:read"])
    session = _FakeSession(execute_result=_FakeResult([]))
    client = _client(viewer, session)

    response = client.get("/api/queues/webhook-deliveries")

    assert response.status_code == 403


def test_queue_metrics_reports_depth_and_oldest_age() -> None:
    admin = _make_user("admin", ["queues:manage"])
    pending = _delivery(status="pending", created_at=datetime.now(timezone.utc) - timedelta(minutes=30))
    failed = _delivery(status="failed")
    session = _FakeSession(execute_result=_FakeResult([pending, failed]))
    redis = _FakeRedis(lengths={"siem:logs:failed": 3, "siem:logs:dead": 1})
    client = _client(admin, session, redis=redis)

    response = client.get("/api/queues/metrics")

    assert response.status_code == 200
    body = response.json()
    assert body["webhook_deliveries"]["pending"] == 1
    assert body["webhook_deliveries"]["failed"] == 1
    assert body["webhook_deliveries"]["oldest_pending_age_seconds"] >= 1800 - 5
    assert body["ingestion_dlq"]["depth"] == 3
    assert body["ingestion_dead_letter"]["depth"] == 1
