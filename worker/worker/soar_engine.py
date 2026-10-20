"""SOAR entry point used by the alert pipeline; the workflow engine lives in worker.soar."""
from __future__ import annotations

import uuid

from worker.soar.engine import dispatch


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
    event: str | None = None,
) -> list[str]:
    """Queue playbook runs for an alert event.

    event is "alert.created" (from the pipeline) or "alert.triaged" (after AI
    triage); each playbook's Trigger picks one, so a playbook runs once per alert.
    """
    if event is None:
        event = "alert.triaged" if ai_verdict is not None else "alert.created"
    trigger = {
        "alert_id":      str(alert_id) if alert_id else None,
        "severity":      rule_match.get("level", "medium"),
        "rule_title":    rule_match.get("title", ""),
        "tags":          rule_match.get("tags", []),
        "mitre_tags":    rule_match.get("mitre_tags", []),
        "source_ip":     source_ip,
        "hostname":      hostname,
        "user_name":     user_name,
        "ai_verdict":    ai_verdict,
        "ai_confidence": ai_confidence,
        "ti_risk_score": ti_risk_score,
    }
    return await dispatch(event, trigger, group_id=group_id)
