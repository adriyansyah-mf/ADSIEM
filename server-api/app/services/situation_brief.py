# server-api/app/services/situation_brief.py
"""Command Center's AI Situation Brief — a short, cited summary of what changed
recently. Read-only, same 9router backend and graceful-degradation contract as
the SOC Assistant (assistant.py): a missing key or a failed provider call never
blocks the analyst, it just degrades to a clear status the frontend can show
alongside the still-fully-functional Priority Queue and Operational Health."""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.llm_client import generate_chat
from app.models.models import Alert, PlatformSetting

_LOOKBACK_HOURS = 24
_MAX_CITED_ALERTS = 8


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return row.value if row and row.value else default


async def get_situation_brief(db: AsyncSession, group_filter: str | None) -> dict:
    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")

    since = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)
    q = select(Alert).where(Alert.created_at >= since, Alert.severity.in_(["critical", "high"]))
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    q = q.order_by(Alert.created_at.desc()).limit(_MAX_CITED_ALERTS)
    alerts = (await db.execute(q)).scalars().all()

    if not api_key:
        return {"status": "unavailable", "reason": "not_configured", "brief": None, "cited_alert_ids": [], "generated_at": None}

    if not alerts:
        return {
            "status": "ok",
            "brief": f"No critical or high severity alerts in the last {_LOOKBACK_HOURS}h.",
            "cited_alert_ids": [],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    facts = "\n".join(
        f"- [{a.id}] {a.severity.upper()} · {a.title} · host={a.hostname or 'unknown'} "
        f"· src_ip={a.source_ip or 'unknown'} · status={a.status} · {a.created_at.isoformat()}"
        for a in alerts
    )
    prompt = (
        "You are writing the top-of-page situation brief for a SOC command center. "
        f"Here are the critical/high alerts from the last {_LOOKBACK_HOURS} hours:\n{facts}\n\n"
        "Write 2-3 sentences for an analyst starting their shift. Distinguish what you "
        "directly observe (counts, hosts, patterns visible in the data above) from what "
        "you infer or suspect — never state an inference as a fact. Do not invent hosts, "
        "IPs, or counts not in the list above. End by naming the single most urgent item "
        "by its alert id in brackets, e.g. [id]. No markdown, plain text only."
    )
    raw = await generate_chat(api_key, model, [{"role": "user", "content": prompt}], max_tokens=300)
    if not raw:
        return {"status": "error", "reason": "provider_unavailable", "brief": None, "cited_alert_ids": [str(a.id) for a in alerts], "generated_at": None}

    return {
        "status": "ok",
        "brief": raw.strip()[:1000],
        "cited_alert_ids": [str(a.id) for a in alerts],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
