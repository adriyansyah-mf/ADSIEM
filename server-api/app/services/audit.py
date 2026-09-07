from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditChainHead, AuditLog

GENESIS_HASH = "0" * 64
UNSCOPED_GROUP = "__unscoped__"

# Detail-dict keys matching any of these substrings (case-insensitive) are
# redacted before the entry is hashed or stored — secrets never enter the
# audit trail, chained or not.
_SECRET_KEY_MARKERS = ("password", "secret", "token", "api_key", "apikey", "hash", "credential")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if any(marker in key.lower() for marker in _SECRET_KEY_MARKERS) else _redact(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_payload(
    *,
    actor_type: str,
    actor_id: UUID | str | None,
    group_id: str,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    detail: dict,
    request_id: str | None,
    created_at: datetime,
) -> dict:
    return {
        "actor_type": actor_type,
        "actor_id": str(actor_id) if actor_id else None,
        "group_id": group_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail,
        "request_id": request_id,
        "created_at": created_at.isoformat(),
    }


def _actor_type_and_ids(actor: object | None) -> tuple[str, UUID | None, str | None]:
    """Resolve (actor_type, actor_id, group_id) from the immutable principal:
    a real `User` row, a Task-3 `ServicePrincipal`, or None (unauthenticated /
    system-originated action, e.g. a failed login)."""
    if actor is None:
        return "system", None, None
    actor_id = getattr(actor, "id", None)
    group_id = getattr(actor, "group_id", None)
    role = getattr(actor, "role", None)
    role_name = getattr(role, "name", None)
    actor_type = "service" if role_name == "service_account" else "user"
    return actor_type, actor_id, group_id


async def _append_chained_entry(
    session: AsyncSession,
    *,
    actor_type: str,
    actor_id: UUID | None,
    group_id: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    detail: dict,
    request_id: str | None,
) -> AuditLog:
    effective_group = group_id or UNSCOPED_GROUP
    created_at = datetime.now(timezone.utc)
    redacted_detail = _redact(detail)

    # Ensure a head row exists before locking it — ON CONFLICT DO NOTHING makes
    # concurrent first-ever appends for a brand-new tenant race-free: whichever
    # transaction's INSERT wins, every racer then finds a row to lock below.
    await session.execute(
        text(
            "INSERT INTO audit_chain_heads (group_id, chain_hash, updated_at) "
            "VALUES (:group_id, :genesis, NOW()) ON CONFLICT (group_id) DO NOTHING"
        ),
        {"group_id": effective_group, "genesis": GENESIS_HASH},
    )
    head = (
        await session.execute(
            select(AuditChainHead).where(AuditChainHead.group_id == effective_group).with_for_update()
        )
    ).scalar_one()
    previous_hash = head.chain_hash

    payload = _canonical_payload(
        actor_type=actor_type,
        actor_id=actor_id,
        group_id=effective_group,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=redacted_detail,
        request_id=request_id,
        created_at=created_at,
    )
    payload_hash = _sha256_hex(_canonical_json(payload))
    chain_hash = _sha256_hex(previous_hash + payload_hash)

    entry = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        group_id=effective_group,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=redacted_detail,
        request_id=request_id,
        created_at=created_at,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        chain_hash=chain_hash,
    )
    session.add(entry)
    head.chain_hash = chain_hash
    head.updated_at = created_at
    await session.commit()
    return entry


async def audit_log(
    db,  # kept for backwards-compatible signature but ignored — opens own session
    actor,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
    *,
    request_id: str | None = None,
) -> None:
    """Append a tamper-evident audit entry.

    `actor` is the immutable principal that performed the action: a `User` ORM
    row, a Task-3 `ServicePrincipal` (service account), or `None` for actions
    with no resolved identity (e.g. a failed login attempt). Always open a
    fresh session so this can run safely as a BackgroundTask after the route's
    request-scoped session has already been closed.
    """
    from app.core.database import AsyncSessionLocal

    actor_type, actor_id, group_id = _actor_type_and_ids(actor)
    async with AsyncSessionLocal() as session:
        await _append_chained_entry(
            session,
            actor_type=actor_type,
            actor_id=actor_id,
            group_id=group_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail or {},
            request_id=request_id,
        )


class AuditChainVerification:
    def __init__(
        self,
        *,
        group_id: str,
        verified: bool,
        verified_count: int,
        total_count: int,
        head_hash_prefix: str | None,
        broken_at_id: str | None = None,
        broken_at_timestamp: datetime | None = None,
    ) -> None:
        self.group_id = group_id
        self.verified = verified
        self.verified_count = verified_count
        self.total_count = total_count
        self.head_hash_prefix = head_hash_prefix
        self.broken_at_id = broken_at_id
        self.broken_at_timestamp = broken_at_timestamp


async def verify_audit_chain(db: AsyncSession, group_id: str) -> AuditChainVerification:
    """Walk the tenant's hash chain by following previous_hash -> chain_hash
    links (not by timestamp or row id) — the chain's own linkage is the sole
    source of order, so verification cannot be fooled by reordering rows.
    """
    effective_group = group_id or UNSCOPED_GROUP
    rows = (
        (await db.execute(select(AuditLog).where(AuditLog.group_id == effective_group)))
        .scalars()
        .all()
    )
    remaining = {row.id: row for row in rows}
    total_count = len(rows)
    current_previous = GENESIS_HASH
    verified_count = 0

    while True:
        candidates = [row for row in remaining.values() if row.previous_hash == current_previous]
        if len(candidates) != 1:
            break
        row = candidates[0]
        payload = _canonical_payload(
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            group_id=row.group_id,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            detail=row.detail,
            request_id=row.request_id,
            created_at=row.created_at,
        )
        expected_payload_hash = _sha256_hex(_canonical_json(payload))
        expected_chain_hash = _sha256_hex(current_previous + expected_payload_hash)
        if expected_payload_hash != row.payload_hash or expected_chain_hash != row.chain_hash:
            return AuditChainVerification(
                group_id=effective_group,
                verified=False,
                verified_count=verified_count,
                total_count=total_count,
                head_hash_prefix=current_previous[:12] if verified_count else None,
                broken_at_id=str(row.id),
                broken_at_timestamp=row.created_at,
            )
        current_previous = expected_chain_hash
        verified_count += 1
        del remaining[row.id]

    if remaining:
        # Rows exist that never linked into the chain from genesis — broken or orphaned.
        broken_row = min(remaining.values(), key=lambda r: r.created_at)
        return AuditChainVerification(
            group_id=effective_group,
            verified=False,
            verified_count=verified_count,
            total_count=total_count,
            head_hash_prefix=current_previous[:12] if verified_count else None,
            broken_at_id=str(broken_row.id),
            broken_at_timestamp=broken_row.created_at,
        )

    return AuditChainVerification(
        group_id=effective_group,
        verified=True,
        verified_count=verified_count,
        total_count=total_count,
        head_hash_prefix=current_previous[:12] if verified_count else None,
    )
