from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio

from app.services.audit import (
    GENESIS_HASH,
    _actor_type_and_ids,
    _redact,
    audit_log,
    verify_audit_chain,
)


def _service_principal(group_id: str = "blue") -> SimpleNamespace:
    role = SimpleNamespace(name="service_account", permissions=frozenset({"alerts:read"}))
    return SimpleNamespace(id=None, group_id=group_id, role=role)


def _user_principal(group_id: str = "blue") -> SimpleNamespace:
    role = SimpleNamespace(name="analyst", permissions=[])
    return SimpleNamespace(id=uuid.uuid4(), group_id=group_id, role=role)


# ── pure logic: actor resolution and redaction ────────────────────


def test_actor_type_resolution_for_none_is_system() -> None:
    actor_type, actor_id, group_id = _actor_type_and_ids(None)
    assert (actor_type, actor_id, group_id) == ("system", None, None)


def test_actor_type_resolution_for_user() -> None:
    user = _user_principal(group_id="red")
    actor_type, actor_id, group_id = _actor_type_and_ids(user)
    assert actor_type == "user"
    assert actor_id == user.id
    assert group_id == "red"


def test_actor_type_resolution_for_service_principal() -> None:
    service = _service_principal(group_id="red")
    actor_type, actor_id, group_id = _actor_type_and_ids(service)
    assert actor_type == "service"
    assert actor_id is None
    assert group_id == "red"


def test_redact_replaces_secret_valued_keys_only() -> None:
    redacted = _redact({"password": "hunter2", "note": "fine", "nested": {"api_key": "abc", "ok": 1}})
    assert redacted == {"password": "[REDACTED]", "note": "fine", "nested": {"api_key": "[REDACTED]", "ok": 1}}


def test_redact_handles_lists() -> None:
    redacted = _redact([{"secret_token": "x"}, {"note": "y"}])
    assert redacted == [{"secret_token": "[REDACTED]"}, {"note": "y"}]


# ── database-backed: chain linking, tamper detection, concurrency ──


@pytest.fixture
def chain_group() -> str:
    return f"chaintest-{uuid.uuid4().hex[:10]}"


@pytest_asyncio.fixture(autouse=True)
async def _cleanup_chain_rows(chain_group: str):
    yield
    from sqlalchemy import text

    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        await session.execute(text("DELETE FROM audit_logs WHERE group_id = :g"), {"g": chain_group})
        await session.execute(text("DELETE FROM audit_chain_heads WHERE group_id = :g"), {"g": chain_group})
        await session.commit()


@pytest.mark.service_e2e
@pytest.mark.asyncio
async def test_chain_links_sequential_entries(chain_group: str) -> None:
    from app.core.database import AsyncSessionLocal

    user = _service_principal(group_id=chain_group)
    await audit_log(None, user, "alert_updated", "alert", "a1", {"status": "investigating"})
    await audit_log(None, user, "alert_updated", "alert", "a1", {"status": "resolved"})

    async with AsyncSessionLocal() as session:
        result = await verify_audit_chain(session, chain_group)

    assert result.verified is True
    assert result.verified_count == 2
    assert result.total_count == 2
    assert result.head_hash_prefix is not None


@pytest.mark.service_e2e
@pytest.mark.asyncio
async def test_first_entry_links_to_genesis(chain_group: str) -> None:
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.models import AuditLog

    user = _service_principal(group_id=chain_group)
    await audit_log(None, user, "case_created", "case", "c1")

    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(select(AuditLog).where(AuditLog.group_id == chain_group))
        ).scalar_one()

    assert row.previous_hash == GENESIS_HASH
    assert row.chain_hash != GENESIS_HASH


@pytest.mark.service_e2e
@pytest.mark.asyncio
async def test_redaction_applies_before_storage_and_hashing(chain_group: str) -> None:
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.models import AuditLog

    user = _service_principal(group_id=chain_group)
    await audit_log(None, user, "webhook_created", "webhook", "w1", {"secret_token": "do-not-store-me"})

    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(select(AuditLog).where(AuditLog.group_id == chain_group))
        ).scalar_one()
        result = await verify_audit_chain(session, chain_group)

    assert row.detail == {"secret_token": "[REDACTED]"}
    assert result.verified is True


@pytest.mark.service_e2e
@pytest.mark.asyncio
async def test_verify_audit_chain_detects_tampered_historical_payload(chain_group: str) -> None:
    from sqlalchemy import select, text

    from app.core.database import AsyncSessionLocal
    from app.models.models import AuditLog

    user = _service_principal(group_id=chain_group)
    await audit_log(None, user, "case_created", "case", "c1")
    await audit_log(None, user, "case_updated", "case", "c1")
    await audit_log(None, user, "case_escalated", "case", "c1")

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(AuditLog).where(AuditLog.group_id == chain_group).order_by(AuditLog.created_at.asc())
            )
        ).scalars().all()
        target = rows[1]  # tamper with the middle entry

    # Tamper via a separate session/connection — a real attacker modifying the
    # database directly would not share the app's SQLAlchemy identity map, and
    # using the same session here would (incorrectly) let verify_audit_chain
    # see cached pre-tamper objects instead of the changed row.
    async with AsyncSessionLocal() as tamper_session:
        await tamper_session.execute(
            text("UPDATE audit_logs SET resource_id = :new_id WHERE id = :id"),
            {"new_id": "TAMPERED", "id": target.id},
        )
        await tamper_session.commit()

    async with AsyncSessionLocal() as session:
        result = await verify_audit_chain(session, chain_group)

    assert result.verified is False
    assert result.broken_at_id == str(target.id)
    assert result.verified_count == 1  # only the first (untouched) entry verifies
    assert result.total_count == 3


@pytest.mark.service_e2e
@pytest.mark.asyncio
async def test_concurrent_appends_produce_one_consistent_chain(chain_group: str) -> None:
    from app.core.database import AsyncSessionLocal

    user = _service_principal(group_id=chain_group)
    concurrency = 12

    await asyncio.gather(
        *(audit_log(None, user, "concurrent_action", "test", str(i)) for i in range(concurrency))
    )

    async with AsyncSessionLocal() as session:
        result = await verify_audit_chain(session, chain_group)

    assert result.verified is True
    assert result.verified_count == concurrency
    assert result.total_count == concurrency
