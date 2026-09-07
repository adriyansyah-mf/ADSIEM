# server-api/app/services/api_keys.py
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models.models import ApiKey

KEY_PREFIX_MARKER = "adsiem_"
_PREFIX_RANDOM_BYTES = 4
_SECRET_BYTES = 32


class ApiKeyError(Exception):
    """Base error for API key operations."""


class PermissionEscalationError(ApiKeyError):
    """Raised when a caller requests permissions it does not itself hold."""


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, secret). Only `full_key` is ever shown to the caller."""
    prefix = f"{KEY_PREFIX_MARKER}{secrets.token_hex(_PREFIX_RANDOM_BYTES)}"
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    return f"{prefix}.{secret}", prefix, secret


def validate_requested_permissions(
    requested: set[str], caller_permissions: set[str], *, caller_is_superadmin: bool
) -> None:
    if caller_is_superadmin:
        return
    escalated = requested - caller_permissions
    if escalated:
        raise PermissionEscalationError(
            f"Cannot grant permissions the caller does not hold: {sorted(escalated)}"
        )


async def create_api_key(
    db: AsyncSession,
    *,
    name: str,
    permissions: list[str],
    group_id: str,
    expires_at: datetime | None,
    created_by: UUID | None,
) -> tuple[ApiKey, str]:
    full_key, prefix, secret = generate_api_key()
    api_key = ApiKey(
        id=uuid4(),
        prefix=prefix,
        secret_hash=hash_password(secret),
        name=name,
        group_id=group_id,
        permissions=sorted(set(permissions)),
        expires_at=expires_at,
        created_by=created_by,
        created_at=datetime.now(timezone.utc),
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return api_key, full_key


def _split_key(token: str) -> tuple[str, str] | None:
    if not token.startswith(KEY_PREFIX_MARKER):
        return None
    prefix, sep, secret = token.partition(".")
    if not sep or not secret:
        return None
    return prefix, secret


async def authenticate_api_key(db: AsyncSession, token: str) -> ApiKey | None:
    """Resolve a presented `Authorization: Bearer <key>` value to its ApiKey row.

    Returns None for any malformed, unknown, revoked, expired, or wrong-secret key —
    callers must not distinguish these cases in the HTTP response.
    """
    parsed = _split_key(token)
    if parsed is None:
        return None
    prefix, secret = parsed
    result = await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    api_key = result.scalar_one_or_none()
    if api_key is None:
        return None
    if api_key.revoked_at is not None:
        return None
    if api_key.expires_at is not None and api_key.expires_at < datetime.now(timezone.utc):
        return None
    if not verify_password(secret, api_key.secret_hash):
        return None
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()
    return api_key


async def revoke_api_key(db: AsyncSession, api_key: ApiKey) -> None:
    api_key.revoked_at = datetime.now(timezone.utc)
    await db.commit()
