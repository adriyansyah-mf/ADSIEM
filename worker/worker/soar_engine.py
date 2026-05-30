"""SOAR engine: evaluate playbook triggers and execute action sequences."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone

import httpx
import structlog
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import (
    AlertNote, AlertSuppression, Case, SoarAction, SoarPlaybook,
)

log = structlog.get_logger()


def _matches_condition(cond: dict, ctx: dict) -> bool:
    field = cond.get("field", "")
    operator = cond.get("operator", "eq")
    value = cond.get("value")
    actual = ctx.get(field)

    if operator == "not_null":
        return actual is not None and actual != ""
    if actual is None:
        return operator == "neq"
    if operator == "eq":
        return str(actual).lower() == str(value).lower()
    if operator == "neq":
        return str(actual).lower() != str(value).lower()
    if operator == "gte":
        try:
            return float(actual) >= float(value)
        except (TypeError, ValueError):
            return False
    if operator == "lte":
        try:
            return float(actual) <= float(value)
        except (TypeError, ValueError):
            return False
    if operator == "in":
        if not isinstance(value, list):
            return False
        return str(actual).lower() in [str(v).lower() for v in value]
    if operator == "contains":
        if isinstance(actual, list):
            return any(str(value).lower() in str(item).lower() for item in actual)
        return str(value).lower() in str(actual or "").lower()
    return False


def _matches_trigger(trigger: dict, ctx: dict) -> bool:
    conditions = trigger.get("conditions", [])
    if not conditions:
        return True
    match_mode = trigger.get("match", "all")
    results = [_matches_condition(c, ctx) for c in conditions]
    return all(results) if match_mode == "all" else any(results)


async def _action_enrich_ioc(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    """Run TI enrichment on the alert's source_ip and attach a note."""
    source_ip = ctx.get("source_ip")
    if not source_ip:
        return
    try:
        from worker.ti.aggregator import EnrichmentAggregator
        from worker.ti.config import TIConfig
        result = await EnrichmentAggregator(TIConfig()).enrich(source_ip)
        note_content = f"**SOAR TI Enrichment** for `{source_ip}`:\n\n{result.summary or 'No significant findings.'}"
    except Exception as exc:
        note_content = f"**SOAR TI Enrichment** failed for `{source_ip}`: {exc}"

    async with AsyncSessionLocal() as db:
        db.add(AlertNote(alert_id=alert_id, content=note_content))
        await db.commit()


async def _action_send_webhook(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    url = params.get("url", "")
    if not url:
        log.warning("soar_webhook_no_url", alert_id=str(alert_id))
        return
    payload = {
        "event": "soar_playbook_fired",
        "alert_id": str(alert_id),
        "title": ctx.get("rule_title", ""),
        "severity": ctx.get("severity", ""),
        "source_ip": ctx.get("source_ip"),
        "hostname": ctx.get("hostname"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        log.info("soar_webhook_sent", alert_id=str(alert_id), url=url)
    except Exception as exc:
        log.warning("soar_webhook_failed", alert_id=str(alert_id), url=url, error=str(exc))


async def _action_create_case(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    title_tpl = params.get("title_template", "SOAR: {alert_title}")
    desc_tpl = params.get("description_template", "Auto-created from alert {alert_id}.")
    try:
        title = title_tpl.format(alert_title=ctx.get("rule_title", ""), alert_id=str(alert_id))
        desc = desc_tpl.format(alert_title=ctx.get("rule_title", ""), alert_id=str(alert_id))
    except KeyError:
        title = title_tpl
        desc = desc_tpl
    async with AsyncSessionLocal() as db:
        existing = (await db.execute(
            select(Case).where(Case.alert_id == alert_id).limit(1)
        )).scalar_one_or_none()
        if existing:
            return
        db.add(Case(
            title=title,
            description=desc,
            severity=ctx.get("severity", "medium"),
            status="open",
            alert_id=alert_id,
            group_id=ctx.get("group_id", "default"),
            created_by_ai=False,
        ))
        await db.commit()
    log.info("soar_case_created", alert_id=str(alert_id))


async def _action_suppress_alert(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    entity_type = params.get("entity_type", "ip")
    reason = params.get("reason", "Automated SOAR suppression")
    group_id = ctx.get("group_id", "default")

    if entity_type == "ip":
        entity_value = ctx.get("source_ip")
    elif entity_type == "hostname":
        entity_value = ctx.get("hostname")
    elif entity_type == "rule_title":
        entity_value = ctx.get("rule_title")
    else:
        entity_value = None

    if not entity_value:
        return

    async with AsyncSessionLocal() as db:
        db.add(AlertSuppression(
            entity_type=entity_type,
            entity_value=entity_value,
            reason=reason,
            group_id=group_id,
            is_active=True,
        ))
        await db.commit()
    log.info("soar_suppression_created", entity_type=entity_type, entity_value=entity_value)


async def _action_add_note(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    content = params.get("content", "Automated SOAR action fired.")
    async with AsyncSessionLocal() as db:
        db.add(AlertNote(alert_id=alert_id, content=content))
        await db.commit()


_ACTION_HANDLERS = {
    "enrich_ioc":      _action_enrich_ioc,
    "send_webhook":    _action_send_webhook,
    "create_case":     _action_create_case,
    "suppress_alert":  _action_suppress_alert,
    "add_note":        _action_add_note,
}


async def run_soar_playbooks(
    alert_id: uuid.UUID,
    rule_match: dict,
    source_ip: str | None,
    hostname: str | None,
    user_name: str | None,
    group_id: str,
    ai_verdict: str | None = None,
    ai_confidence: float | None = None,
    ti_risk_score: float | None = None,
) -> None:
    ctx = {
        "severity":     rule_match.get("level", "medium"),
        "rule_title":   rule_match.get("title", ""),
        "tags":         rule_match.get("tags", []),
        "mitre_tags":   rule_match.get("mitre_tags", []),
        "source_ip":    source_ip,
        "hostname":     hostname,
        "user_name":    user_name,
        "group_id":     group_id,
        "ai_verdict":   ai_verdict,
        "ai_confidence": ai_confidence,
        "ti_risk_score": ti_risk_score,
    }

    async with AsyncSessionLocal() as db:
        q = select(SoarPlaybook).where(
            SoarPlaybook.is_enabled == True,
            (SoarPlaybook.group_id == group_id) | (SoarPlaybook.group_id == "default"),
        )
        playbooks = (await db.execute(q)).scalars().all()

        matched = []
        for pb in playbooks:
            trigger = pb.trigger_conditions or {}
            if _matches_trigger(trigger, ctx):
                actions_q = (
                    select(SoarAction)
                    .where(SoarAction.playbook_id == pb.id)
                    .order_by(SoarAction.order_index)
                )
                actions = (await db.execute(actions_q)).scalars().all()
                matched.append((pb.name, actions))

    for pb_name, actions in matched:
        log.info("soar_playbook_matched", playbook=pb_name, alert_id=str(alert_id))
        for action in actions:
            handler = _ACTION_HANDLERS.get(action.action_type)
            if not handler:
                log.warning("soar_unknown_action", action_type=action.action_type)
                continue
            try:
                await handler(alert_id, ctx, action.params or {})
            except Exception as exc:
                log.error("soar_action_failed", action_type=action.action_type,
                          playbook=pb_name, error=str(exc))
