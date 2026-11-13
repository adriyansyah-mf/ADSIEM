# worker/worker/entity_risk.py
"""Unified per-entity risk: every new alert (Sigma, IOA, IoC matches,
behaviour findings, UEBA, YARA, agent tamper...) adds risk to its host and
its user, so many small signals on one machine add up instead of sitting in
separate queues.

- points by severity (POINTS), plus NEW_TACTIC_BONUS the first time a MITRE
  tactic shows up for the entity within TACTIC_WINDOW: an entity moving
  through the kill chain climbs faster than one repeating the same thing
- decays with a 24 h half-life; capped at 100
- risk-based alerting: when an entity reaches `entity_risk_alert_threshold`
  (platform setting, default 70) with at least MIN_TACTICS tactics in the
  last 24 h, one "[Risk]" alert is raised (at most once per RISK_ALERT_EVERY),
  carrying the contributing alerts. Those alerts add no risk themselves.

Deduplicated and suppressed alerts add nothing (create_alert only calls
record() for a new alert row). Never raises into alert creation."""
from __future__ import annotations

import math
import time
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker import settings_cache
from worker.database import AsyncSessionLocal
from worker.ti.mitre import stage_for_techniques

log = structlog.get_logger()

RULE_ID = "entity-risk"
POINTS = {"informational": 2, "info": 2, "low": 5, "medium": 15, "high": 30, "critical": 50}
NEW_TACTIC_BONUS = 10
HALF_LIFE = 24 * 3600
TACTIC_WINDOW = 24 * 3600
MIN_TACTICS = 2
DEFAULT_THRESHOLD = 70
RISK_ALERT_EVERY = 24 * 3600
MAX_RECENT = 20
_IGNORED_USERS = {"", "-", "n/a", "none", "null", "unknown"}

TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
}
_SOURCES = (("ueba-", "ueba"), ("rule-ioa-", "ioa"), ("rule-ioc-", "ioc"), ("rule-behavior-", "behavior"),
            ("rule-yara-", "yara"), ("rule-known-malware", "malware"), ("rule-siem-agent", "agent_tamper"),
            ("rule-suricata", "network_ids"), ("rule-zeek", "network_ids"), ("rule-win-app-control", "app_control"))


def decayed(score: float, seconds: float) -> float:
    return score if seconds <= 0 else score * math.pow(0.5, seconds / HALF_LIFE)


def source_of(rule_match: dict) -> str:
    rid = str(rule_match.get("id") or "").lower()
    for prefix, name in _SOURCES:
        if rid.startswith(prefix):
            return name
    return "sigma"


def tactics_of(rule_match: dict, techniques: list[str]) -> list[str]:
    """MITRE tactics from Sigma tags (attack.execution), else from the techniques' kill-chain stage."""
    out = []
    for tag in list(rule_match.get("tags") or []) + list(rule_match.get("mitre_tags") or []):
        t = str(tag).lower()
        if t.startswith("attack."):
            name = t[len("attack."):].replace("-", "_")
            if name in TACTICS and name not in out:
                out.append(name)
    if not out and techniques:
        stage = stage_for_techniques(techniques)
        name = stage.lower().replace(" ", "_").replace("-", "_")
        if name in TACTICS:
            out.append(name)
    return out


def apply(state: dict, *, points: float, tactics: list[str], entry: dict, now: float) -> tuple[dict, float]:
    """New state after one alert; returns (state, points added including the tactic bonus)."""
    seen = dict(state.get("tactics") or {})
    fresh = [t for t in tactics if now - float(seen.get(t, 0)) > TACTIC_WINDOW]
    added = points + NEW_TACTIC_BONUS * len(fresh)
    for t in tactics:
        seen[t] = now
    risk = min(100.0, decayed(float(state.get("risk_score") or 0.0), now - float(state.get("updated") or now)) + added)
    sources = dict(state.get("sources") or {})
    sources[entry["source"]] = int(sources.get(entry["source"], 0)) + 1
    recent = [{**entry, "points": round(added, 1)}] + list(state.get("recent") or [])
    return {
        "risk_score": round(risk, 2),
        "peak_score": round(max(risk, float(state.get("peak_score") or 0.0)), 2),
        "alert_count": int(state.get("alert_count") or 0) + 1,
        "tactics": seen, "sources": sources, "recent": recent[:MAX_RECENT], "updated": now,
    }, added


def active_tactics(state: dict, now: float) -> list[str]:
    return sorted(t for t, at in (state.get("tactics") or {}).items() if now - float(at) <= TACTIC_WINDOW)


def wants_risk_alert(state: dict, last_risk_alert: float | None, threshold: float, now: float) -> bool:
    return (state["risk_score"] >= threshold and len(active_tactics(state, now)) >= MIN_TACTICS
            and (last_risk_alert is None or now - last_risk_alert >= RISK_ALERT_EVERY))


def entities_of(hostname: str | None, user: str | None, rule_match: dict) -> list[tuple[str, str]]:
    out = []
    if hostname and str(hostname).strip().lower() not in _IGNORED_USERS:
        out.append(("host", str(hostname).strip()[:255]))
    fields = rule_match.get("matched_fields") or {}
    user = user or fields.get("user.name") or fields.get("User") or fields.get("TargetUserName")
    if user and str(user).strip().lower() not in _IGNORED_USERS:
        out.append(("user", str(user).strip()[:255]))
    return out


async def record(*, alert_id, rule_match: dict, techniques: list[str], group_id: str,
                 hostname: str | None, user: str | None, agent_id=None, sessions=None) -> list[str]:
    """Add one new alert to its entities' risk; raise risk alerts that are due.
    `sessions` is the caller's session factory (create_alert passes its own, so
    the alert and its risk share one database binding). Returns the risk
    alerts raised (entity values), for tests and logs."""
    if rule_match.get("id") == RULE_ID:
        return []  # a risk alert must not feed itself
    points = POINTS.get(str(rule_match.get("level") or "").lower(), 5)
    tactics = tactics_of(rule_match, techniques)
    source = source_of(rule_match)
    now = time.time()
    try:
        threshold = float(await settings_cache.get_setting("entity_risk_alert_threshold", str(DEFAULT_THRESHOLD))
                          or DEFAULT_THRESHOLD)
    except (TypeError, ValueError):
        threshold = DEFAULT_THRESHOLD
    entry = {"alert_id": str(alert_id), "title": str(rule_match.get("title") or "")[:200],
             "severity": str(rule_match.get("level") or ""), "source": source, "tactics": tactics,
             "at": datetime.fromtimestamp(now, timezone.utc).isoformat()}
    due = []
    for entity_type, value in entities_of(hostname, user, rule_match):
        state, raise_alert = await _update(entity_type, value, group_id or "default", points, tactics, entry,
                                           now, threshold, sessions or AsyncSessionLocal)
        if raise_alert:
            due.append((entity_type, value, state))
    for entity_type, value, state in due:
        await _raise(entity_type, value, state, group_id or "default", agent_id, hostname, now)
    return [v for _, v, _ in due]


async def _update(entity_type, value, group_id, points, tactics, entry, now, threshold,
                  sessions) -> tuple[dict, bool]:
    from worker.models import EntityRisk
    key = {"entity_type": entity_type, "entity_value": value, "group_id": group_id}
    async with sessions() as db:
        # one row per entity; FOR UPDATE serialises the worker replicas on it
        await db.execute(pg_insert(EntityRisk).values(**key, risk_score=0.0, peak_score=0.0, alert_count=0,
                                                      tactics={}, sources={}, recent=[],
                                                      updated_at=datetime.now(timezone.utc))
                         .on_conflict_do_nothing())
        row = (await db.execute(select(EntityRisk).filter_by(**key).with_for_update())).scalar_one()
        state = {"risk_score": row.risk_score, "peak_score": row.peak_score, "alert_count": row.alert_count,
                 "tactics": row.tactics, "sources": row.sources, "recent": row.recent,
                 "updated": row.updated_at.timestamp() if row.updated_at else now}
        state, _ = apply(state, points=points, tactics=tactics, entry=entry, now=now)
        last = row.risk_alert_at.timestamp() if row.risk_alert_at else None
        raise_alert = wants_risk_alert(state, last, threshold, now)
        row.risk_score, row.peak_score, row.alert_count = state["risk_score"], state["peak_score"], state["alert_count"]
        row.tactics, row.sources, row.recent = state["tactics"], state["sources"], state["recent"]
        row.updated_at = row.last_alert_at = datetime.fromtimestamp(now, timezone.utc)
        if raise_alert:
            row.risk_alert_at = row.updated_at
        await db.commit()
    return state, raise_alert


async def _raise(entity_type, value, state, group_id, agent_id, hostname, now) -> None:
    from worker.alert_manager import create_alert
    risk = state["risk_score"]
    tactics = active_tactics(state, now)
    label = "Host" if entity_type == "host" else "User"
    top = state["recent"][:8]
    await create_alert(
        rule_match={
            "id": RULE_ID,
            "title": f"[Risk] {label} {value}: risk {risk:.0f}/100 across {len(tactics)} tactics",
            "level": "critical" if risk >= 90 else "high",
            "tags": ["entity_risk", f"entity_risk.{entity_type}"] + [f"attack.{t}" for t in tactics],
            "mitre_tags": [f"attack.{t}" for t in tactics],
            # handed to the AI analyst as the event context
            "matched_fields": {"entity_type": entity_type, "entity_value": value, "risk_score": risk,
                               "tactics": tactics, "alert_count": state["alert_count"], "sources": state["sources"],
                               "contributing_alerts": [f"{e['severity']}: {e['title']}" for e in top]},
        },
        event_id=None, agent_id=agent_id if entity_type == "host" else None, group_id=group_id, source_ip=None,
        hostname=value if entity_type == "host" else hostname,
        user=value if entity_type == "user" else None,
    )
    log.info("entity_risk_alert", entity_type=entity_type, entity_value=value, risk=risk, tactics=tactics)
