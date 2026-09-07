# server-api/app/api/routes/retention_policies.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.es_client import count_by_query
from app.models.models import PlatformSetting, RetentionPolicy, User
from app.services.audit import audit_log

router = APIRouter(prefix="/api/retention-policies", tags=["retention-policies"])
Perm = require_permission("settings:manage")


class RetentionPolicyUpdate(BaseModel):
    log_retention_days: int | None = Field(default=None, ge=0)
    alert_retention_days: int | None = Field(default=None, ge=0)
    storage_quota_docs: int | None = Field(default=None, ge=0)


async def _global_int_setting(db: AsyncSession, key: str, default: int) -> int:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    if row is None or not row.value:
        return default
    try:
        return int(row.value)
    except ValueError:
        return default


async def _effective_policy(db: AsyncSession, target_group: str) -> dict:
    policy = (
        await db.execute(select(RetentionPolicy).where(RetentionPolicy.group_id == target_group))
    ).scalar_one_or_none()
    global_log_days = max(
        await _global_int_setting(db, "retention_raw_logs_days", 30),
        await _global_int_setting(db, "retention_events_days", 90),
    )
    global_alert_days = await _global_int_setting(db, "retention_alerts_days", 180)
    log_days = policy.log_retention_days if policy and policy.log_retention_days is not None else global_log_days
    alert_days = policy.alert_retention_days if policy and policy.alert_retention_days is not None else global_alert_days
    return {
        "group_id": target_group,
        "log_retention_days": log_days,
        "alert_retention_days": alert_days,
        "storage_quota_docs": policy.storage_quota_docs if policy else None,
        "is_override": policy is not None,
    }


@router.get("")
async def get_retention_policy(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant's policy to view"),
):
    """Effective retention policy for a tenant: an override where set, the
    platform default otherwise. Same shape as sla-policies: a tenant-scoped
    caller always sees their own tenant; a superadmin passes ?group_id=."""
    target_group = group_filter if group_filter is not None else group_id
    if target_group is None:
        raise HTTPException(status_code=422, detail="group_id is required for superadmin callers")
    return await _effective_policy(db, target_group)


@router.put("")
async def upsert_retention_policy(
    body: RetentionPolicyUpdate,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant to set the override for"),
):
    """Each field is independently nullable: leaving a field null means
    "inherit the platform default for that field", not "disable retention
    for it" -- an explicit 0 is what disables retention/quota."""
    target_group = group_filter if group_filter is not None else (group_id or current_user.group_id or "default")
    existing = (
        await db.execute(select(RetentionPolicy).where(RetentionPolicy.group_id == target_group))
    ).scalar_one_or_none()
    if existing is None:
        policy = RetentionPolicy(
            group_id=target_group,
            log_retention_days=body.log_retention_days,
            alert_retention_days=body.alert_retention_days,
            storage_quota_docs=body.storage_quota_docs,
        )
        db.add(policy)
    else:
        existing.log_retention_days = body.log_retention_days
        existing.alert_retention_days = body.alert_retention_days
        existing.storage_quota_docs = body.storage_quota_docs
    await db.commit()
    background.add_task(
        audit_log, db, current_user, "retention_policy_updated", "retention_policy", target_group,
        {
            "log_retention_days": body.log_retention_days,
            "alert_retention_days": body.alert_retention_days,
            "storage_quota_docs": body.storage_quota_docs,
        },
    )
    return await _effective_policy(db, target_group)


@router.get("/usage")
async def get_retention_usage(
    db: Annotated[AsyncSession, Depends(get_db)],
    _current_user: Annotated[User, Depends(Perm)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)] = None,
    group_id: str | None = Query(None, description="Superadmin only: which tenant's usage to view"),
):
    """Current log-document count against the tenant's storage quota (a
    document-count cap, not a byte-accurate size -- the shared `logs` index
    isn't partitioned per tenant, so precise per-tenant byte accounting
    would need per-tenant indices, which is out of scope here)."""
    target_group = group_filter if group_filter is not None else group_id
    if target_group is None:
        raise HTTPException(status_code=422, detail="group_id is required for superadmin callers")
    policy = (
        await db.execute(select(RetentionPolicy).where(RetentionPolicy.group_id == target_group))
    ).scalar_one_or_none()
    doc_count = await count_by_query({"term": {"group_id": target_group}})
    quota = policy.storage_quota_docs if policy else None
    return {
        "group_id": target_group,
        "log_doc_count": doc_count,
        "storage_quota_docs": quota,
        "over_quota": bool(quota and doc_count > quota),
    }
