"""Audit log: who did what, from which address, and whether it worked
(services/audit.py), plus a check that nothing in it was changed or removed
(services/audit_chain.py). There is deliberately no route that edits or
deletes an entry."""
import csv
import io
from datetime import datetime
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import es_client
from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import AuditLog, User
from app.services import audit_chain

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])
Admin = require_permission("settings:manage")
CHECKPOINT_INDEX = "audit_checkpoints"  # written by worker/audit_checkpoint.py
EXPORT_LIMIT = 50_000


def _query(group_filter, action, actor, ip, outcome, since, until, q):
    stmt = select(AuditLog)
    if group_filter is not None:
        stmt = stmt.where(AuditLog.group_id == group_filter)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_name.ilike(f"%{actor}%"))
    if ip:
        stmt = stmt.where(AuditLog.ip_address == ip)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at < until)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(AuditLog.action.ilike(like), AuditLog.resource_id.ilike(like),
                              AuditLog.actor_name.ilike(like), AuditLog.request.ilike(like)))
    return stmt


def _out(r: AuditLog) -> dict:
    return {
        "id": str(r.id),
        "seq": r.seq,
        "actor_id": str(r.actor_id) if r.actor_id else None,
        "actor_name": r.actor_name,
        "group_id": r.group_id,
        "action": r.action,
        "outcome": r.outcome,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "detail": r.detail,
        "ip_address": r.ip_address,
        "user_agent": r.user_agent,
        "request": r.request,
        "hash": r.hash,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


Outcome = Optional[Literal["success", "failure", "denied"]]


@router.get("")
async def list_audit_logs(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _: Annotated[User, Depends(Admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100_000),
    action: Optional[str] = None,
    actor: Optional[str] = Query(None, max_length=255),
    ip: Optional[str] = Query(None, max_length=64),
    outcome: Outcome = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = Query(None, max_length=200),
):
    stmt = _query(group_filter, action, actor, ip, outcome, since, until, q)
    rows = (await db.execute(stmt.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit))).scalars().all()
    return [_out(r) for r in rows]


@router.get("/export.csv")
async def export_audit_logs(
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _: Annotated[User, Depends(Admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    action: Optional[str] = None,
    actor: Optional[str] = Query(None, max_length=255),
    ip: Optional[str] = Query(None, max_length=64),
    outcome: Outcome = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = Query(None, max_length=200),
):
    stmt = _query(group_filter, action, actor, ip, outcome, since, until, q)
    rows = (await db.execute(stmt.order_by(AuditLog.created_at.asc()).limit(EXPORT_LIMIT))).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["seq", "created_at", "actor_name", "action", "outcome", "resource_type", "resource_id",
            "ip_address", "user_agent", "request", "group_id", "hash", "detail"]
    w.writerow(cols)
    for r in rows:
        o = _out(r)
        # a leading = + - @ would run as a formula in a spreadsheet; actor names come from login attempts
        w.writerow([("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v)
                    for v in (o[c] if c != "detail" else str(o["detail"]) for c in cols)])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})


async def latest_checkpoint() -> dict | None:
    try:
        resp = await es_client._get_client().post(f"/{CHECKPOINT_INDEX}/_search", json={
            "size": 1, "sort": [{"seq": "desc"}], "_source": ["seq", "hash", "recorded_at"]})
        if resp.status_code != 200:
            return None
        hits = resp.json().get("hits", {}).get("hits", [])
        return hits[0]["_source"] if hits else None
    except Exception:  # noqa: BLE001 — ES down: the chain is still checked
        return None


@router.get("/verify")
async def verify_audit_chain(
    user: Annotated[User, Depends(Admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Recompute every hash and link. One chain covers all groups, so group
    admins get the verdict and superadmins also the row numbers."""
    result = await audit_chain.verify(db, await latest_checkpoint())
    if user.role.name != "superadmin":
        result = {"ok": result["ok"], "checked": result["checked"],
                  "problems": [{"problem": p["problem"]} for p in result["problems"]],
                  "checkpoint": {"status": result["checkpoint"].get("status")}}
    return result
