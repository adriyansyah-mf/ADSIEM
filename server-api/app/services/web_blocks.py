# server-api/app/services/web_blocks.py
"""Web Protection lists (spec B1): per-group blocklist, allowlist and policy,
and the agent delta sync. Entries and policies take the next web_block_seq on
every change; allowlist changes bump the platform setting web_block_rules_seq,
which forces every agent to resync (the allowlist filters the whole set)."""
from __future__ import annotations

import time

from sqlalchemy import func, or_, select, text, update

from app.models.models import Agent, PlatformSetting, WebAllowRule, WebBlockEntry, WebBlockPolicy, _web_block_seq
from app.services.web_page import DEFAULT_PAGE_HTML
from worker.web_domains import BUILTIN_ALLOWLIST, allow_match

FEED_GROUP = "*"
RULES_SEQ_KEY = "web_block_rules_seq"
POLICY_DEFAULTS = {"enabled": False, "feed_enabled": False, "alert_enabled": False, "alert_block_days": 30,
                   "max_entries": 50000, "page_html": None, "contact": ""}
SYNC_PAGE = 5000
CACHE_SECONDS = 30.0
_SOURCE_RANK = {"manual": 0, "alert": 1}

_version_cache: dict[str, tuple[float, str]] = {}


def invalidate() -> None:
    _version_cache.clear()


def next_seq():
    return _web_block_seq.next_value()


async def policy_for(db, group_id: str) -> dict:
    row = await db.get(WebBlockPolicy, group_id) or await db.get(WebBlockPolicy, "default")
    out = dict(POLICY_DEFAULTS)
    if row is not None:
        out.update({key: getattr(row, key) for key in POLICY_DEFAULTS})
    out["seq"] = int(row.seq) if row is not None else 0
    out["custom_page"] = out["page_html"] is not None
    if out["page_html"] is None:
        out["page_html"] = DEFAULT_PAGE_HTML
    return out


async def allow_rules(db, group_id: str) -> list[tuple[str, bool]]:
    rows = (await db.execute(select(WebAllowRule.domain, WebAllowRule.include_subdomains).where(
        WebAllowRule.enabled.is_(True), WebAllowRule.group_id.in_((group_id, FEED_GROUP))))).all()
    return [(domain, include) for domain, include in rows]


async def mark_rules_changed(db) -> None:
    """Call in the same transaction as an allowlist change; the caller commits."""
    seq = (await db.execute(select(next_seq()))).scalar_one()
    await db.merge(PlatformSetting(key=RULES_SEQ_KEY, value=str(seq), is_secret=False,
                                   description="Web Protection allowlist change marker"))
    invalidate()


async def _rules_seq(db) -> int:
    value = (await db.execute(select(PlatformSetting.value).where(PlatformSetting.key == RULES_SEQ_KEY))).scalar_one_or_none()
    try:
        return int(value or 0)
    except ValueError:
        return 0


async def seed_builtin_allowlist(db) -> None:
    inserted = 0
    for domain, include in BUILTIN_ALLOWLIST:
        result = await db.execute(text(
            "INSERT INTO web_allowlist (id, group_id, domain, include_subdomains, builtin, enabled, created_at) "
            "VALUES (gen_random_uuid(), :g, :d, :inc, true, true, now()) "
            "ON CONFLICT (group_id, domain) DO NOTHING"), {"g": FEED_GROUP, "d": domain, "inc": include})
        inserted += result.rowcount or 0
    if inserted:
        await mark_rules_changed(db)
    await db.commit()


async def expire(db) -> int:
    result = await db.execute(update(WebBlockEntry).where(
        WebBlockEntry.status == "active", WebBlockEntry.expires_at.is_not(None), WebBlockEntry.expires_at <= func.now(),
    ).values(status="removed", seq=next_seq(), updated_at=func.now()))
    if result.rowcount:
        await db.commit()
        invalidate()
    return result.rowcount or 0


def _groups(group_id: str, policy: dict) -> list[str]:
    return [group_id, FEED_GROUP] if policy["feed_enabled"] else [group_id]


async def _top_seq(db, group_id: str, policy: dict) -> int:
    entries = (await db.execute(select(func.coalesce(func.max(WebBlockEntry.seq), 0)).where(
        WebBlockEntry.group_id.in_(_groups(group_id, policy))))).scalar_one()
    return max(int(entries), await _rules_seq(db), policy["seq"])


async def agent_version(db, agent: Agent) -> str:
    """For the heartbeat: "" when off, else the newest relevant seq, "+" when an entry is due to expire (cached briefly)."""
    if not agent.approved:
        return ""
    group = agent.group_id or "default"
    hit = _version_cache.get(group)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    policy = await policy_for(db, group)
    version = ""
    if policy["enabled"]:
        # Read-only here (the heartbeat's session must not commit): a due expiry
        # changes the version so the agent syncs, and the sync endpoint expires it.
        due = (await db.execute(select(func.count()).select_from(WebBlockEntry).where(
            WebBlockEntry.group_id.in_(_groups(group, policy)), WebBlockEntry.status == "active",
            WebBlockEntry.expires_at.is_not(None), WebBlockEntry.expires_at <= func.now()))).scalar_one()
        version = str(await _top_seq(db, group, policy)) + ("+" if due else "")
    _version_cache[group] = (time.monotonic(), version)
    return version


def _policy_out(policy: dict) -> dict:
    return {key: policy[key] for key in ("enabled", "page_html", "contact", "max_entries")}


async def _active(db, groups: list[str], domains: list[str] | None) -> dict[str, WebBlockEntry]:
    """Per domain, the active unexpired entry to report: manual over alert over feeds, newest first."""
    query = select(WebBlockEntry).where(
        WebBlockEntry.group_id.in_(groups), WebBlockEntry.status == "active",
        or_(WebBlockEntry.expires_at.is_(None), WebBlockEntry.expires_at > func.now()))
    if domains is not None:
        query = query.where(WebBlockEntry.domain.in_(domains))
    best: dict[str, WebBlockEntry] = {}
    for row in (await db.execute(query)).scalars().all():
        current = best.get(row.domain)
        key = (_SOURCE_RANK.get(row.source, 2), -row.created_at.timestamp())
        if current is None or key < (_SOURCE_RANK.get(current.source, 2), -current.created_at.timestamp()):
            best[row.domain] = row
    return best


async def delta(db, group_id: str, since: int, continuing: bool = False, limit: int = SYNC_PAGE,
                rules: int = 0) -> dict:
    """Changes above `since` for one group. reset: the agent drops its set first
    (first sync, allowlist/policy change, or a seq it cannot have); changes are
    then the active set. With more, the agent continues from seq with continuing=true."""
    await expire(db)
    policy = await policy_for(db, group_id)
    if not policy["enabled"]:
        return {"policy": _policy_out(policy), "seq": 0, "reset": True, "more": False, "rules": 0,
                "changes": []}
    groups = _groups(group_id, policy)
    top = await _top_seq(db, group_id, policy)
    marker = max(await _rules_seq(db), policy["seq"])
    if continuing:
        # a rule/policy change between pages invalidates what was already delivered
        reset = rules != marker
    else:
        reset = since <= 0 or since > top or marker > since
    if reset:
        since = 0
    rows = (await db.execute(select(WebBlockEntry.domain, WebBlockEntry.seq).where(
        WebBlockEntry.group_id.in_(groups), WebBlockEntry.seq > since).order_by(WebBlockEntry.seq).limit(limit))).all()
    more = len(rows) == limit
    domains = list(dict.fromkeys(domain for domain, _ in rows))
    active = await _active(db, groups, domains)
    rules = await allow_rules(db, group_id)
    changes = []
    for domain in domains:
        entry = active.get(domain)
        if entry is not None and allow_match(domain, rules) is None:
            changes.append({"domain": domain, "action": "block", "source": entry.source, "reason": entry.reason})
        elif not reset:
            changes.append({"domain": domain, "action": "remove"})
    return {"policy": _policy_out(policy), "seq": rows[-1].seq if more else top, "reset": reset, "more": more,
            "rules": marker, "changes": changes}


async def blocked_domains(db, group_id: str | None, domains) -> set[str]:
    """Which of `domains` agents of `group_id` block (None = blocked for any group)."""
    domains = list(dict.fromkeys(domains))
    if not domains:
        return set()
    if group_id is None:
        rows = (await db.execute(select(WebBlockEntry.domain).where(
            WebBlockEntry.domain.in_(domains), WebBlockEntry.status == "active",
            or_(WebBlockEntry.expires_at.is_(None), WebBlockEntry.expires_at > func.now())))).scalars().all()
        return set(rows)
    policy = await policy_for(db, group_id)
    if not policy["enabled"]:
        return set()
    rules = await allow_rules(db, group_id)
    active = await _active(db, _groups(group_id, policy), domains)
    return {domain for domain in active if allow_match(domain, rules) is None}
