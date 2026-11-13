# server-api/app/api/routes/ip_blocks.py
"""IP IoC blocklist: agents sync it here (agent/internal/ipblock); the dashboard
manages it. Whether agents drop or only report listed addresses is the group
policy's ip_ioc (app/services/agent_policy.py)."""
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent, get_scoped_group, require_permission
from app.models.models import Agent, IPBlockEntry, User
from app.services import ip_blocks
from app.services.audit import audit_log
from worker.ip_iocs import ALL_GROUPS

agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class DeltaRequest(BaseModel):
    since: int = 0
    continuing: bool = False


@agent_router.post("/ip-blocklist")
async def agent_ip_blocklist(
    body: DeltaRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    group = agent.group_id or "default"
    out = await ip_blocks.delta(db, group, max(body.since, 0), body.continuing)
    # equals the heartbeat's ip_blocklist_version once the agent has every page
    version = f"{group}:{out['seq']}:{out['mode']}" if out["mode"] != "off" and not out["more"] else ""
    return {**out, "group": group, "version": version}


router = APIRouter(tags=["ip-blocks"])
Read = Depends(require_permission("alerts:read"))
Manage = Depends(require_permission("agents:manage"))


def _target_group(group_filter: Optional[str], requested: Optional[str]) -> str:
    """The caller's own group, or any group (including "*") for a superadmin."""
    if group_filter is not None:
        if requested and requested != group_filter:
            raise HTTPException(status_code=404, detail="Group not found")
        return group_filter
    return requested or "default"


def _visible(group_filter: Optional[str]):
    return true() if group_filter is None else IPBlockEntry.group_id.in_((group_filter, ALL_GROUPS))


def _out(r: IPBlockEntry) -> dict:
    return {"id": str(r.id), "cidr": r.cidr, "group_id": r.group_id, "source": r.source, "status": r.status,
            "reason": r.reason, "alert_id": str(r.alert_id) if r.alert_id else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None}


def _future(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and (value if value.tzinfo else value.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    return value


class BlockIn(BaseModel):
    value: str = Field(..., max_length=64)
    reason: str = Field("", max_length=500)
    expires_at: Optional[datetime] = None
    group_id: Optional[str] = Field(None, max_length=100)

    _check_expiry = field_validator("expires_at")(_future)


class BulkIn(BaseModel):
    action: Literal["block", "unblock"]
    values: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=500)
    ids: list[UUID] = Field(default_factory=list, max_length=500)
    reason: str = Field("", max_length=500)
    expires_at: Optional[datetime] = None
    group_id: Optional[str] = Field(None, max_length=100)

    _check_expiry = field_validator("expires_at")(_future)


@router.get("/api/ip-blocks")
async def list_blocks(
    q: str = Query("", max_length=64), source: str = "", status: str = "active",
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), _=Read, group: Optional[str] = Depends(get_scoped_group),
):
    query = select(IPBlockEntry).where(_visible(group))
    if q.strip():
        query = query.where(IPBlockEntry.cidr.ilike(f"%{q.strip()}%"))
    if source:
        query = query.where(IPBlockEntry.source == source)
    if status:
        query = query.where(IPBlockEntry.status == status)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(IPBlockEntry.updated_at.desc()).offset(offset).limit(limit))).scalars().all()
    mode = await ip_blocks.mode_for(db, group or "default")
    return {"total": total, "mode": mode, "items": [_out(r) for r in rows]}


async def _block_one(db: AsyncSession, user: User, target: str, value: str, reason: str,
                     expires_at: Optional[datetime]) -> IPBlockEntry:
    row = await ip_blocks.block_ip(db, user, target, value, reason, expires_at)
    await audit_log(db, user.id, "ip_block.add", "ip_block", str(row.id), {"cidr": row.cidr, "group_id": target})
    return row


async def _unblock_one(db: AsyncSession, user: User, group: Optional[str], entry_id: UUID) -> dict:
    row = await db.get(IPBlockEntry, entry_id)
    if row is None or (group is not None and row.group_id != group):
        # an entry for every group ("*") is a superadmin's to remove
        raise HTTPException(status_code=404, detail="Block not found")
    if row.status != "removed":
        await ip_blocks.remove(db, row)
    await audit_log(db, user.id, "ip_block.remove", "ip_block", str(row.id), {"cidr": row.cidr})
    return {"status": "removed"}


@router.post("/api/ip-blocks", status_code=201)
async def add_block(body: BlockIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                    group: Optional[str] = Depends(get_scoped_group)):
    target = _target_group(group, body.group_id)
    return _out(await _block_one(db, user, target, body.value, body.reason, body.expires_at))


@router.delete("/api/ip-blocks/{entry_id}")
async def remove_block(entry_id: UUID, db: AsyncSession = Depends(get_db), user: User = Manage,
                       group: Optional[str] = Depends(get_scoped_group)):
    return await _unblock_one(db, user, group, entry_id)


@router.post("/api/ip-blocks/bulk")
async def bulk_blocks(body: BulkIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                      group: Optional[str] = Depends(get_scoped_group)):
    """Block up to 500 values or unblock up to 500 ids; each item succeeds or reports its own error."""
    done, errors = 0, []
    if body.action == "block":
        target = _target_group(group, body.group_id)
        for value in body.values:
            try:
                await _block_one(db, user, target, value, body.reason, body.expires_at)
                done += 1
            except HTTPException as exc:
                errors.append({"value": value, "detail": str(exc.detail)})
    else:
        for entry_id in body.ids:
            try:
                await _unblock_one(db, user, group, entry_id)
                done += 1
            except HTTPException as exc:
                errors.append({"value": str(entry_id), "detail": str(exc.detail)})
    return {"done": done, "errors": errors}
