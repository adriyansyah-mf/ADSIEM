# server-api/app/api/routes/syslog_sources.py
"""Agentless syslog senders (worker/worker/syslog_receiver.py reads this table).

A source maps a sender CIDR to a group and a log type. The receiver drops
messages from unregistered addresses and lists them under /unknown, which only
a superadmin may read: those senders belong to no group yet."""
import ipaddress
import json
import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import fetch_scoped, get_current_user, get_scoped_group, require_permission
from app.core.redis_client import get_redis
from app.models.models import SyslogSource, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/syslog-sources", tags=["syslog"])

# Shared with worker/worker/syslog_receiver.py
UNKNOWN_KEY = "siem:syslog:unknown"
_LOG_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,99}$")
# broader than this would claim other tenants' senders, so only a superadmin may
_MIN_PREFIX = {4: 16, 6: 48}


def normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError("cidr must be an IP address or network, e.g. 10.0.0.1 or 10.0.0.0/24") from exc


def _check_log_type(value: str) -> str:
    value = value.strip()
    if not _LOG_TYPE_RE.match(value):
        raise ValueError("log_type: lowercase letters, digits, '_', '.', '-' (e.g. fortigate_traffic, cef)")
    return value


class SyslogSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    cidr: str
    log_type: str
    enabled: bool = True
    group_id: str | None = None  # superadmin only; others always get their own group

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return normalize_cidr(v)

    @field_validator("log_type")
    @classmethod
    def _log_type(cls, v: str) -> str:
        return _check_log_type(v)


class SyslogSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    cidr: str | None = None
    log_type: str | None = None
    enabled: bool | None = None

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str | None) -> str | None:
        return None if v is None else normalize_cidr(v)

    @field_validator("log_type")
    @classmethod
    def _log_type(cls, v: str | None) -> str | None:
        return None if v is None else _check_log_type(v)


class SyslogSourceOut(BaseModel):
    id: UUID
    name: str
    group_id: str
    cidr: str
    log_type: str
    enabled: bool
    message_count: int
    last_seen_at: datetime | None
    created_at: datetime | None

    model_config = {"from_attributes": True}


def _check_breadth(cidr: str, user: User) -> None:
    net = ipaddress.ip_network(cidr)
    if user.role.name != "superadmin" and net.prefixlen < _MIN_PREFIX[net.version]:
        raise HTTPException(403, f"Only a superadmin may register a network broader than /{_MIN_PREFIX[net.version]}")


async def _commit(db: AsyncSession, cidr: str) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, f"{cidr} is already registered as a syslog source") from exc


@router.get("", response_model=list[SyslogSourceOut])
async def list_sources(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _: Annotated[User, Depends(get_current_user)],
):
    q = select(SyslogSource).order_by(SyslogSource.name)
    if group_filter:
        q = q.where(SyslogSource.group_id == group_filter)
    return (await db.execute(q)).scalars().all()


@router.get("/unknown")
async def unknown_senders(
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    """Senders the receiver dropped in the last 7 days, newest first."""
    if user.role.name != "superadmin":
        raise HTTPException(403, "Only a superadmin may list unregistered senders")
    rows = []
    for ip, raw in (await redis.hgetall(UNKNOWN_KEY) or {}).items():
        try:
            entry = json.loads(raw)
        except (TypeError, ValueError):
            continue
        rows.append({"ip": ip, "count": entry.get("count", 0), "last_seen": entry.get("last_seen"),
                     "proto": entry.get("proto"), "sample": entry.get("sample", "")})
    return sorted(rows, key=lambda r: r["last_seen"] or "", reverse=True)


@router.post("", response_model=SyslogSourceOut, status_code=201)
async def create_source(
    body: SyslogSourceCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
):
    _check_breadth(body.cidr, user)
    group_id = group_filter or body.group_id or user.group_id
    row = SyslogSource(name=body.name.strip(), cidr=body.cidr, log_type=body.log_type,
                       enabled=body.enabled, group_id=group_id, created_by=user.id)
    db.add(row)
    await _commit(db, body.cidr)
    await db.refresh(row)
    try:  # registered now: stop listing it as unknown
        net = ipaddress.ip_network(row.cidr)
        known = [ip for ip in (await redis.hkeys(UNKNOWN_KEY) or []) if ipaddress.ip_address(ip) in net]
        if known:
            await redis.hdel(UNKNOWN_KEY, *known)
    except Exception:  # noqa: BLE001 — cosmetic; the entry expires on its own
        pass
    await audit_log(db, user.id, "syslog_source.create", "syslog_source", str(row.id),
                    {"name": row.name, "cidr": row.cidr, "log_type": row.log_type, "group_id": row.group_id})
    return row


@router.put("/{source_id}", response_model=SyslogSourceOut)
async def update_source(
    source_id: UUID,
    body: SyslogSourceUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    row = await fetch_scoped(db, SyslogSource, source_id, group_filter)
    changes = body.model_dump(exclude_none=True)
    if "cidr" in changes:
        _check_breadth(changes["cidr"], user)
    if "name" in changes:
        changes["name"] = changes["name"].strip()
    for key, value in changes.items():
        setattr(row, key, value)
    await _commit(db, row.cidr)
    await db.refresh(row)
    await audit_log(db, user.id, "syslog_source.update", "syslog_source", str(row.id), changes)
    return row


@router.delete("/{source_id}", status_code=204)
async def delete_source(
    source_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("agents:manage"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    row = await fetch_scoped(db, SyslogSource, source_id, group_filter)
    detail = {"name": row.name, "cidr": row.cidr}
    await db.delete(row)
    await db.commit()
    await audit_log(db, user.id, "syslog_source.delete", "syslog_source", str(source_id), detail)
