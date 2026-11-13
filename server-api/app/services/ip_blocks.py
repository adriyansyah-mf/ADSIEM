# server-api/app/services/ip_blocks.py
"""IP IoC blocklist: per-group entries plus the "*" list every group gets, and
the agent delta sync (agent/internal/ipblock). Every change takes the next
ip_block_seq; the group policy's ip_ioc (off, detect, block) decides whether
agents sync at all and whether they drop or only report."""
from __future__ import annotations

import time
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from app.models.models import Agent, IPBlockEntry, User, _ip_block_seq
from app.services import agent_policy
from worker.ip_iocs import ALL_GROUPS, IP_BLOCK_SEQ_LOCK, IPError, normalize

SYNC_PAGE = 5000
CACHE_SECONDS = 30.0
_SOURCE_RANK = {"manual": 0, "soar": 1, "alert": 2}

_version_cache: dict[str, tuple[float, str]] = {}


def invalidate() -> None:
    _version_cache.clear()


async def lock_seq_writes(db) -> None:
    """Serialize seq-assigning transactions until commit (see web_blocks.lock_seq_writes)."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": IP_BLOCK_SEQ_LOCK})


def next_seq():
    return _ip_block_seq.next_value()


async def mode_for(db, group_id: str) -> str:
    return (await agent_policy.effective(db, group_id))["settings"].get("ip_ioc", "block")


async def block_ip(db, user: User, group: str, value: str, reason: str, expires_at: datetime | None) -> IPBlockEntry:
    """Block one address or CIDR for `group` ("*" = every group) as a manual entry.
    Commits. Raises HTTPException 422 (not blockable) or 409 (concurrent change).
    The caller audits (ip_block.add)."""
    try:
        cidr = normalize(value, allow_private=True)
    except IPError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await lock_seq_writes(db)
    row = (await db.execute(select(IPBlockEntry).where(
        IPBlockEntry.group_id == group, IPBlockEntry.cidr == cidr, IPBlockEntry.source == "manual"))).scalar_one_or_none()
    if row is None:
        created_by = user.id if await db.get(User, user.id) is not None else None
        row = IPBlockEntry(cidr=cidr, group_id=group, source="manual", created_by=created_by)
        db.add(row)
    row.status, row.reason, row.expires_at, row.seq = "active", reason.strip(), expires_at, next_seq()
    try:
        await db.flush()
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="This item was changed at the same time; try again")
    await db.refresh(row)
    invalidate()
    return row


async def remove(db, row: IPBlockEntry) -> None:
    """Mark an entry removed (agents drop it on their next sync). Commits."""
    await lock_seq_writes(db)
    row.status, row.seq = "removed", next_seq()
    await db.commit()
    invalidate()


async def expire(db) -> int:
    due = (await db.execute(select(func.count()).select_from(IPBlockEntry).where(
        IPBlockEntry.status == "active", IPBlockEntry.expires_at.is_not(None),
        IPBlockEntry.expires_at <= func.now()))).scalar_one()
    if not due:
        return 0
    await lock_seq_writes(db)
    result = await db.execute(update(IPBlockEntry).where(
        IPBlockEntry.status == "active", IPBlockEntry.expires_at.is_not(None), IPBlockEntry.expires_at <= func.now(),
    ).values(status="removed", seq=next_seq(), updated_at=func.now()))
    await db.commit()
    if result.rowcount:
        invalidate()
    return result.rowcount or 0


def _groups(group_id: str) -> list[str]:
    return [group_id, ALL_GROUPS]


async def _top_seq(db, group_id: str) -> int:
    return int((await db.execute(select(func.coalesce(func.max(IPBlockEntry.seq), 0)).where(
        IPBlockEntry.group_id.in_(_groups(group_id))))).scalar_one())


async def agent_version(db, agent: Agent) -> str:
    """For the heartbeat: "" when ip_ioc is off, else "<group>:<seq>:<mode>",
    with "+" appended when an entry is due to expire (cached briefly)."""
    if not agent.approved:
        return ""
    group = agent.group_id or "default"
    hit = _version_cache.get(group)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    mode = await mode_for(db, group)
    version = ""
    if mode != "off":
        # read-only here: a due expiry changes the version, the sync endpoint expires it
        due = (await db.execute(select(func.count()).select_from(IPBlockEntry).where(
            IPBlockEntry.group_id.in_(_groups(group)), IPBlockEntry.status == "active",
            IPBlockEntry.expires_at.is_not(None), IPBlockEntry.expires_at <= func.now()))).scalar_one()
        version = f"{group}:{await _top_seq(db, group)}:{mode}" + ("+" if due else "")
    _version_cache[group] = (time.monotonic(), version)
    return version


async def _active(db, groups: list[str], cidrs: list[str] | None) -> dict[str, IPBlockEntry]:
    """Per CIDR, the active unexpired entry to report: manual over soar over alert over feeds, newest first."""
    query = select(IPBlockEntry).where(
        IPBlockEntry.group_id.in_(groups), IPBlockEntry.status == "active",
        or_(IPBlockEntry.expires_at.is_(None), IPBlockEntry.expires_at > func.now()))
    if cidrs is not None:
        query = query.where(IPBlockEntry.cidr.in_(cidrs))
    best: dict[str, IPBlockEntry] = {}
    for row in (await db.execute(query)).scalars().all():
        current = best.get(row.cidr)
        key = (_SOURCE_RANK.get(row.source, 3), -row.created_at.timestamp())
        if current is None or key < (_SOURCE_RANK.get(current.source, 3), -current.created_at.timestamp()):
            best[row.cidr] = row
    return best


async def delta(db, group_id: str, since: int, continuing: bool = False, limit: int = SYNC_PAGE) -> dict:
    """Changes above `since` for one group. reset: the agent drops its set first
    (first sync, or a seq it cannot have); with more, it continues from seq."""
    await expire(db)
    # wait for in-flight seq writers: every row below the top seq we report must be visible
    await db.execute(text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": IP_BLOCK_SEQ_LOCK})
    mode = await mode_for(db, group_id)
    if mode == "off":
        return {"mode": mode, "seq": 0, "reset": True, "more": False, "changes": []}
    groups = _groups(group_id)
    top = await _top_seq(db, group_id)
    reset = not continuing and (since <= 0 or since > top)
    if reset:
        since = 0
    rows = (await db.execute(select(IPBlockEntry.cidr, IPBlockEntry.seq).where(
        IPBlockEntry.group_id.in_(groups), IPBlockEntry.seq > since).order_by(IPBlockEntry.seq).limit(limit))).all()
    more = len(rows) == limit
    cidrs = list(dict.fromkeys(cidr for cidr, _ in rows))
    active = await _active(db, groups, cidrs)
    changes = []
    for cidr in cidrs:
        entry = active.get(cidr)
        if entry is not None:
            changes.append({"cidr": cidr, "action": "block", "source": entry.source, "reason": entry.reason})
        elif not reset:
            changes.append({"cidr": cidr, "action": "remove"})
    return {"mode": mode, "seq": rows[-1].seq if more else top, "reset": reset, "more": more, "changes": changes}
