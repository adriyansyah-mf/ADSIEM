# worker/worker/hunter.py
"""Threat Hunt Agent — traces IoCs through historical alerts, events, and FIM data."""
import json
import uuid
import asyncio
import structlog
from datetime import datetime, timezone

from sqlalchemy import select, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from worker.database import AsyncSessionLocal
from worker.models import Alert, ThreatHunt
from worker.settings_cache import get_setting
from worker.config import NINEROUTER_API_KEY, NINEROUTER_MODEL
from worker.llm_client import _llm_post
from worker.es_client import search as es_search

log = structlog.get_logger()

_HUNT_SYSTEM_PROMPT = """You are an elite threat hunter and SOC analyst. You are given an IoC (Indicator of Compromise) and a timeline of historical security alerts and events where it appeared.

Your job is to:
1. Determine the attack narrative — what happened, in what order, and why
2. Map to MITRE ATT&CK techniques
3. Assess if this is an isolated incident or an ongoing campaign
4. Give a concrete risk level and recommended actions

Respond ONLY in valid JSON:
{
  "risk_level": "critical|high|medium|low",
  "attack_narrative": "<2-4 sentences in English describing what happened and the attack progression>",
  "mitre_techniques": ["T1190", "T1059", ...],
  "campaign_assessment": "isolated|likely_campaign|confirmed_campaign",
  "kill_chain_phase": "recon|initial_access|execution|persistence|lateral_movement|exfiltration|impact|unknown",
  "recommended_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "confidence": 0.0
}"""


async def _call_llm(ioc_type: str, ioc_value: str, timeline_text: str) -> dict:
    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    model = await get_setting("ninerouter_model", NINEROUTER_MODEL)
    if not api_key:
        return {"risk_level": "unknown", "attack_narrative": "AI not configured", "confidence": 0.0}

    prompt = f"""Threat Hunt Results for IoC: {ioc_type}={ioc_value}

Timeline of appearances ({len(timeline_text.splitlines())} entries):
{timeline_text[:3000]}

Analyze this IoC's historical footprint and determine the attack pattern."""

    try:
        result = await _llm_post(api_key, {
            "model": model,
            "messages": [
                {"role": "system", "content": _HUNT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.15,
            "max_tokens": 700,
        })
        content = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.error("hunt_llm_failed", error=str(e))
        return {"risk_level": "unknown", "attack_narrative": f"Analysis failed: {e}", "confidence": 0.0}


async def _search_alerts(db: AsyncSession, ioc_type: str, ioc_value: str) -> list[Alert]:
    """Find all alerts matching this IoC."""
    if ioc_type == "ip":
        q = select(Alert).where(Alert.source_ip == ioc_value)
    elif ioc_type == "hostname":
        q = select(Alert).where(Alert.hostname == ioc_value)
    elif ioc_type == "user":
        # need to join via events (ES) — query matching events first
        ev_hits = await es_search(
            {"term": {"user_name": ioc_value}}, size=200,
            sort=[{"created_at": "desc"}],
        )
        ev_ids = [uuid.UUID(h["id"]) for h in ev_hits]
        if not ev_ids:
            return []
        q = select(Alert).where(Alert.event_id.in_(ev_ids))
    elif ioc_type == "hash":
        # FIM SHA256 — find via raw text match in fim_events
        fim_q = text("SELECT agent_id FROM fim_events WHERE sha256 = :val LIMIT 50")
        result = await db.execute(fim_q, {"val": ioc_value})
        agent_ids = [str(r[0]) for r in result]
        if not agent_ids:
            return []
        from sqlalchemy import cast
        from sqlalchemy.dialects.postgresql import UUID as PGUUID
        q = select(Alert).where(Alert.agent_id.in_([uuid.UUID(a) for a in agent_ids]))
    else:
        return []

    result = await db.execute(q.order_by(desc(Alert.created_at)).limit(100))
    return result.scalars().all()


async def _search_events(ioc_type: str, ioc_value: str) -> list[dict]:
    """Find events (ES) matching this IoC."""
    if ioc_type == "ip":
        query = {"term": {"source_ip": ioc_value}}
    elif ioc_type == "hostname":
        query = {"term": {"decoded_fields.hostname.keyword": ioc_value}}
    elif ioc_type == "user":
        query = {"term": {"user_name": ioc_value}}
    else:
        return []
    return await es_search(query, size=100, sort=[{"created_at": "desc"}])


def _build_timeline(alerts: list[Alert], events: list[dict]) -> list[dict]:
    """Merge alerts and events into a unified sorted timeline."""
    entries = []
    for a in alerts:
        entries.append({
            "time": a.created_at.isoformat() if a.created_at else None,
            "type": "alert",
            "severity": a.severity,
            "title": a.title,
            "source_ip": a.source_ip,
            "hostname": a.hostname,
            "id": str(a.id),
        })
    for e in events:
        entries.append({
            "time": e.get("created_at"),
            "type": "event",
            "category": e.get("event_category"),
            "action": e.get("event_action"),
            "source_ip": e.get("source_ip"),
            "user": e.get("user_name"),
            "id": e.get("id"),
        })
    entries.sort(key=lambda x: x.get("time") or "")
    return entries


def _timeline_to_text(ioc_type: str, ioc_value: str, timeline: list[dict]) -> str:
    lines = []
    for e in timeline:
        ts = (e.get("time") or "")[:19]
        if e["type"] == "alert":
            lines.append(f"[{ts}] ALERT({e['severity'].upper()}) — {e['title']} | ip={e.get('source_ip')} host={e.get('hostname')}")
        else:
            lines.append(f"[{ts}] EVENT — {e.get('category')}/{e.get('action')} | ip={e.get('source_ip')} user={e.get('user')}")
    return "\n".join(lines) if lines else f"No historical data found for {ioc_type}={ioc_value}"


async def run_hunt(hunt_id: str) -> None:
    async with AsyncSessionLocal() as db:
        hunt = await db.get(ThreatHunt, uuid.UUID(hunt_id))
        if not hunt:
            return

        hunt.status = "running"
        await db.commit()
        log.info("hunt_started", id=hunt_id, ioc_type=hunt.ioc_type, ioc_value=hunt.ioc_value)

        try:
            alerts = await _search_alerts(db, hunt.ioc_type, hunt.ioc_value)
            events = await _search_events(hunt.ioc_type, hunt.ioc_value)

            # FIM count for hash IoCs
            fim_count = 0
            if hunt.ioc_type == "hash":
                r = await db.execute(
                    text("SELECT COUNT(*) FROM fim_events WHERE sha256 = :val"),
                    {"val": hunt.ioc_value}
                )
                fim_count = r.scalar() or 0

            timeline = _build_timeline(alerts, events)
            timeline_text = _timeline_to_text(hunt.ioc_type, hunt.ioc_value, timeline)

            analysis = await _call_llm(hunt.ioc_type, hunt.ioc_value, timeline_text)

            hunt.status = "done"
            hunt.alert_count = len(alerts)
            hunt.event_count = len(events)
            hunt.fim_count = fim_count
            hunt.risk_level = analysis.get("risk_level", "unknown")
            hunt.timeline = timeline
            hunt.analysis = json.dumps(analysis, ensure_ascii=False)
            hunt.related_alert_ids = [str(a.id) for a in alerts]
            hunt.completed_at = datetime.now(timezone.utc)
            await db.commit()

            log.info("hunt_done", id=hunt_id, alerts=len(alerts), events=len(events),
                     risk=hunt.risk_level)

        except Exception as e:
            log.error("hunt_failed", id=hunt_id, error=str(e))
            hunt.status = "failed"
            hunt.analysis = json.dumps({"attack_narrative": str(e)})
            await db.commit()


async def hunt_loop() -> None:
    """Poll for pending hunts and run them."""
    from worker.models import ThreatHunt
    while True:
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(ThreatHunt)
                    .where(ThreatHunt.status == "pending")
                    .order_by(ThreatHunt.created_at)
                    .limit(3)
                )
                pending = result.scalars().all()
                for hunt in pending:
                    hunt.status = "running"
                await db.commit()
                hunt_ids = [str(h.id) for h in pending]

            for hunt_id in hunt_ids:
                await run_hunt(hunt_id)

        except Exception as e:
            log.error("hunt_loop_error", error=str(e))

        await asyncio.sleep(5)
