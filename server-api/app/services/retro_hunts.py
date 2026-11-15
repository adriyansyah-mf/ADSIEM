"""Queue retro-hunts (worker/retro_hunt.py runs them).

An analyst starts one from the Retro-hunt page. Adding an IP to the IP
blocklist, a domain to Web Protection or a hash to Malware hashes queues one
automatically (setting retro_hunt_on_block), so the first question about a
new indicator, "has it already been here?", is answered without asking.
Feeds never trigger one: they add thousands of entries."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select

from app.models.models import PlatformSetting, RetroHunt

IOC_TYPES = ("ip", "domain", "hash", "url", "text")
MAX_DAYS = 365
DEDUP_WINDOW = timedelta(hours=1)


def valid_ioc(ioc_type: str, value: str) -> str | None:
    """The normalised value, or None when it is not an indicator of that type
    (the same rules as worker/retro_hunt.valid_ioc)."""
    value = (value or "").strip()
    if not value or len(value) > 2048 or ioc_type not in IOC_TYPES:
        return None
    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if ioc_type == "hash":
        v = value.lower()
        return v if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v) else None
    if ioc_type == "domain":
        v = value.lower().rstrip(".")
        return v if "." in v and " " not in v and "/" not in v else None
    return value if len(value) >= 4 else None


def single_ip(cidr: str) -> str | None:
    """The address of a one-address network (a /32 or /128 block), else None."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    return str(net.network_address) if net.num_addresses == 1 else None


async def _setting(db, key: str, default: str) -> str:
    row = await db.get(PlatformSetting, key)
    return (row.value or "").strip() if row and (row.value or "").strip() else default


async def actor(db, user_id: UUID | None) -> UUID | None:
    """created_by is a foreign key to users: a caller without a users row is recorded as NULL."""
    from app.models.models import User
    return user_id if user_id is not None and await db.get(User, user_id) is not None else None


async def default_days(db) -> int:
    try:
        return max(1, min(MAX_DAYS, int(await _setting(db, "retro_hunt_days", "30"))))
    except ValueError:
        return 30


async def enqueue_ioc(db, ioc_type: str, value: str, group_id: str, trigger: str,
                      user_id: UUID | None = None, days: int | None = None,
                      create_alerts: bool = True) -> RetroHunt | None:
    """Queue an IOC hunt; None when the value is no indicator, automatic hunts
    are off, or the same IOC was hunted for this group within the hour. Commits."""
    clean = valid_ioc(ioc_type, value)
    if clean is None:
        return None
    if trigger != "manual" and (await _setting(db, "retro_hunt_on_block", "true")).lower() != "true":
        return None
    since = datetime.now(timezone.utc) - DEDUP_WINDOW
    recent = (await db.execute(select(RetroHunt.id).where(
        RetroHunt.kind == "ioc", RetroHunt.ioc_type == ioc_type, RetroHunt.ioc_value == clean,
        RetroHunt.group_id == group_id, RetroHunt.created_at >= since,
        RetroHunt.status.in_(("pending", "running", "done")),
    ).limit(1))).scalar_one_or_none()
    if recent is not None:
        return None
    hunt = RetroHunt(kind="ioc", ioc_type=ioc_type, ioc_value=clean, group_id=group_id, trigger=trigger,
                     days=days or await default_days(db), create_alerts=create_alerts,
                     created_by=await actor(db, user_id))
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


async def enqueue_safely(db, *args, **kwargs) -> None:
    """enqueue_ioc for the blocklist routes, in a session of its own: the
    route's session (and the block row it is about to return) is never
    committed, rolled back or expired by it, and a hunt that cannot be queued
    never fails the block itself. `db` is the route's session, unused."""
    from app.core.database import AsyncSessionLocal
    try:
        async with AsyncSessionLocal() as own:
            await enqueue_ioc(own, *args, **kwargs)
    except Exception:  # noqa: BLE001
        import structlog
        structlog.get_logger().warning("retro_hunt_enqueue_failed", args=[str(a)[:80] for a in args[:3]])
