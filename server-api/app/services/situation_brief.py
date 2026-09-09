# server-api/app/services/situation_brief.py
"""Command Center's AI Situation Brief — a short, cited summary of what changed
recently. Read-only, same 9router backend and graceful-degradation contract as
the SOC Assistant (assistant.py): a missing key or a failed provider call never
blocks the analyst, it just degrades to a clear status the frontend can show
alongside the still-fully-functional Priority Queue and Operational Health.

Regenerates at most once per _CACHE_TTL (per group) — every LLM call here costs
real 9router/provider tokens, and the frontend used to trigger one on every
page load plus a 5-minute poll. `force=True` (the dashboard's manual refresh
button) bypasses the cache for an explicit, deliberate regeneration."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.llm_client import generate_chat
from app.models.models import Alert, PlatformSetting, SituationBriefCache

_LOOKBACK_HOURS = 24
_MAX_CONTEXT_ALERTS = 20
_MAX_CITED_ALERTS = 8
_CACHE_TTL = timedelta(hours=24)


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return row.value if row and row.value else default


def _cache_key(group_filter: str | None) -> str:
    return group_filter or "global"


async def _read_cache(db: AsyncSession, group_filter: str | None) -> dict | None:
    row = (await db.execute(
        select(SituationBriefCache).where(SituationBriefCache.group_key == _cache_key(group_filter))
    )).scalar_one_or_none()
    if not row or datetime.now(timezone.utc) - row.generated_at > _CACHE_TTL:
        return None
    return {
        "status": row.status,
        "brief": row.brief,
        "cited_alert_ids": row.cited_alert_ids,
        "generated_at": row.generated_at.isoformat(),
        "cached": True,
    }


async def _write_cache(db: AsyncSession, group_filter: str | None, result: dict) -> None:
    stmt = pg_insert(SituationBriefCache).values(
        group_key=_cache_key(group_filter),
        status=result["status"],
        brief=result["brief"],
        cited_alert_ids=result["cited_alert_ids"],
        generated_at=datetime.now(timezone.utc),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[SituationBriefCache.group_key],
        set_={"status": stmt.excluded.status, "brief": stmt.excluded.brief,
              "cited_alert_ids": stmt.excluded.cited_alert_ids, "generated_at": stmt.excluded.generated_at},
    )
    await db.execute(stmt)
    await db.commit()


async def get_situation_brief(db: AsyncSession, group_filter: str | None, force: bool = False) -> dict:
    if not force:
        cached = await _read_cache(db, group_filter)
        if cached:
            return cached

    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")

    since = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)
    q = select(Alert).where(Alert.created_at >= since, Alert.severity.in_(["critical", "high"]))
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    q = q.order_by(Alert.created_at.desc()).limit(_MAX_CONTEXT_ALERTS)
    alerts = (await db.execute(q)).scalars().all()

    if not api_key:
        return {"status": "unavailable", "reason": "not_configured", "brief": None, "cited_alert_ids": [], "generated_at": None, "cached": False}

    if not alerts:
        result = {
            "status": "ok",
            "brief": f"No critical or high severity alerts in the last {_LOOKBACK_HOURS}h.",
            "cited_alert_ids": [],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        await _write_cache(db, group_filter, result)
        return {**result, "cached": False}

    facts = "\n".join(
        f"- [{a.id}] {a.severity.upper()} · {a.title} · host={a.hostname or 'unknown'} "
        f"· src_ip={a.source_ip or 'unknown'} · status={a.status} · {a.created_at.isoformat()}"
        for a in alerts
    )
    # Close the read transaction (settings + alerts queries above) before the
    # LLM call below, which can take 60-90s+ on a slow/retrying provider —
    # an open transaction for that long can block unrelated DDL elsewhere.
    await db.commit()
    prompt = (
        "You are writing the daily top-of-page situation brief for a SOC command center, "
        "read once per shift by an analyst who has not yet looked at anything else today. "
        f"Here are the critical/high alerts from the last {_LOOKBACK_HOURS} hours "
        f"(up to {_MAX_CONTEXT_ALERTS} most recent):\n{facts}\n\n"
        "Write a thorough shift-start briefing, 6-10 sentences, covering in order: "
        "(1) an overview of volume and severity mix, "
        "(2) any host, source IP, or alert-type that recurs across multiple entries and what that pattern might indicate, "
        "(3) the rough time distribution (e.g. clustered overnight vs spread through the day), "
        "(4) anything already acknowledged/resolved vs still open that the analyst should know about, "
        "(5) a concrete recommended starting point for the shift. "
        "Distinguish what you directly observe (counts, hosts, patterns visible in the data above) from what "
        "you infer or suspect — never state an inference as a fact. Do not invent hosts, "
        "IPs, or counts not in the list above. End by naming the single most urgent item "
        "by its alert id in brackets, e.g. [id]. No markdown, plain text only."
    )
    raw = await generate_chat(api_key, model, [{"role": "user", "content": prompt}], max_tokens=700)
    cited = [str(a.id) for a in alerts[:_MAX_CITED_ALERTS]]
    if not raw:
        return {"status": "error", "reason": "provider_unavailable", "brief": None, "cited_alert_ids": cited, "generated_at": None, "cached": False}

    result = {
        "status": "ok",
        "brief": raw.strip()[:3000],
        "cited_alert_ids": cited,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    await _write_cache(db, group_filter, result)
    return {**result, "cached": False}
