# worker/worker/webblock_auto.py
"""Web Protection alert auto-block: a triaged outbound alert (C2, exfiltration,
execution) whose domain/URL indicator is malicious blocks that domain for the
alert's group, for the policy's alert_block_days.

Runs only for AI-triaged alerts: alerts below ai_min_severity never reach the
triage graph, so they are never auto-blocked. Every condition must hold:
group policy `enabled` and `alert_enabled`; family in OUTBOUND_FAMILIES; the
indicator is malicious by TI (URLhaus listed / VirusTotal >= 3) or the AI
verdict is escalate/create_case; the domain is not allowlisted for the group;
the alert is not itself a web_block event. Never raises into triage."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import structlog
from sqlalchemy import text

from worker import alert_iocs, case_grouping
from worker.database import AsyncSessionLocal
from worker.web_domains import WEB_BLOCK_SEQ_LOCK, DomainError, allow_match, normalize

log = structlog.get_logger()

BLOCKING_VERDICTS = {"escalate", "create_case"}
_MAX_TITLE = 120

_UPSERT = text("""
INSERT INTO web_block_entries (id, domain, group_id, source, status, reason, alert_id,
                               created_at, updated_at, expires_at, seq)
VALUES (gen_random_uuid(), :domain, :group, 'alert', 'active', :reason, :alert, now(), now(), :expires,
        nextval('web_block_seq'))
ON CONFLICT (group_id, domain, source) DO UPDATE
SET status = 'active', reason = EXCLUDED.reason, alert_id = EXCLUDED.alert_id,
    expires_at = EXCLUDED.expires_at, updated_at = now(), seq = nextval('web_block_seq')
WHERE web_block_entries.status <> 'active'
   OR (web_block_entries.expires_at IS NOT NULL AND web_block_entries.expires_at < EXCLUDED.expires_at)
RETURNING domain
""")


# no user acts here: actor_id stays NULL, the action name marks it as automatic
_AUDIT = text("""
INSERT INTO audit_logs (id, actor_id, group_id, action, resource_type, resource_id, detail, created_at)
VALUES (gen_random_uuid(), NULL, :group, 'web_block.auto_block', 'web_block', :target,
        CAST(:detail AS jsonb), now())
""")


def _field(obj, name: str):
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def is_web_block_event(fields: dict | None) -> bool:
    return str((fields or {}).get("event.action") or "").lower() == "web_block"


def _host(value: str) -> str | None:
    try:
        return normalize(value)
    except DomainError:
        return None


def candidates(alert_id: str, group_id: str, title: str, fields: dict | None, extracted,
               exclusions) -> dict[str, bool]:
    """Normalized domains of the alert's domain and URL indicators -> True when any came
    from the decoded event fields (the destination), False when only from alert text/TI."""
    meta = alert_iocs.AlertMeta(alert_id=alert_id, group_id=group_id, severity="medium", hostname=None,
                                agent_id=None, rule_title=title, created_at=datetime.now(timezone.utc))
    out: dict[str, bool] = {}
    for _id, doc in alert_iocs.collect(meta, None, fields, extracted, exclusions):
        if doc["type"] in ("domain", "url") and (host := _host(doc["value"])):
            out[host] = out.get(host, False) or doc["origin"] == "event"
    return out


def ti_malicious_hosts(enrichment) -> set[str]:
    hosts = set()
    for rep in getattr(enrichment, "reputation", None) or []:
        if _field(rep, "malicious") and _field(rep, "ioc_type") in ("domain", "url"):
            if host := _host(str(_field(rep, "ioc_value") or "")):
                hosts.add(host)
    return hosts


async def _policy(db, group_id: str) -> tuple[bool, bool, int]:
    res = await db.execute(
        text("SELECT group_id, enabled, alert_enabled, alert_block_days FROM web_block_policies "
             "WHERE group_id IN (:g, 'default')"), {"g": group_id})
    rows = {r.group_id: r for r in res}
    row = rows.get(group_id) or rows.get("default")
    if row is None:
        return False, False, 30
    return bool(row.enabled), bool(row.alert_enabled), int(row.alert_block_days or 30)


async def _allow_rules(db, group_id: str) -> list[tuple[str, bool]]:
    res = await db.execute(text("SELECT domain, include_subdomains FROM web_allowlist "
                                "WHERE group_id IN (:g, '*') AND enabled"), {"g": group_id})
    return [(r.domain, r.include_subdomains) for r in res]


async def maybe_block(alert_id: str, group_id: str, title: str, verdict: str, fields: dict | None,
                      enrichment, tags: list | None = None, threat_type: str | None = None) -> list[str]:
    """Block the alert's malicious domains; returns the domains whose entry changed."""
    try:
        return await _maybe_block(alert_id, group_id, title, verdict, fields, enrichment, tags, threat_type)
    except Exception:
        log.exception("webblock_auto_failed", alert_id=alert_id)
        return []


async def _maybe_block(alert_id, group_id, title, verdict, fields, enrichment, tags, threat_type) -> list[str]:
    if not alert_id or not group_id or is_web_block_event(fields):
        return []
    if case_grouping.attack_family(tags, threat_type, title) not in case_grouping.OUTBOUND_FAMILIES:
        return []
    async with AsyncSessionLocal() as db:
        enabled, alert_enabled, days = await _policy(db, group_id)
        if not (enabled and alert_enabled):
            return []
        rules = await _allow_rules(db, group_id)
    cands = candidates(alert_id, group_id, title, fields, getattr(enrichment, "iocs", None),
                       await alert_iocs._exclusions())
    cands = {d: ev for d, ev in cands.items() if not allow_match(d, rules)}
    bad = ti_malicious_hosts(enrichment)
    # TI-malicious hosts are blocked whatever their origin; the AI verdict alone only
    # vouches for the event's destination, not for every host mentioned in the alert text.
    chosen = [d for d, from_event in cands.items()
              if d in bad or (verdict in BLOCKING_VERDICTS and from_event)]
    if not chosen:
        return []
    # each domain cites its own evidence: a TI-malicious host cites TI, any other the verdict
    evidence = {d: "threat intelligence malicious" if d in bad else f"AI verdict {verdict}" for d in chosen}
    reasons = {d: f"Alert: {(title or '')[:_MAX_TITLE]} ({evidence[d]})" for d in chosen}
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    async with AsyncSessionLocal() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": WEB_BLOCK_SEQ_LOCK})
        changed = []
        for domain in chosen:
            res = await db.execute(_UPSERT, {"domain": domain, "group": group_id, "reason": reasons[domain],
                                             "alert": UUID(str(alert_id)), "expires": expires})
            if res.first():
                changed.append(domain)
        if changed:
            await db.execute(
                text("INSERT INTO alert_notes (id, alert_id, content, created_at) "
                     "VALUES (gen_random_uuid(), :a, :c, now())"),
                {"a": UUID(str(alert_id)),
                 "c": f"Web Protection: blocked {', '.join(changed)} for group {group_id} "
                      f"until {expires:%Y-%m-%d}"})
            await db.execute(_AUDIT, {
                "group": group_id, "target": ", ".join(changed),
                "detail": json.dumps({"alert_id": str(alert_id), "group_id": group_id, "domains": changed,
                                      "expires_at": expires.isoformat(),
                                      "evidence": {d: evidence[d] for d in changed}})})
        await db.commit()
    if changed:
        log.info("webblock_auto_blocked", alert_id=alert_id, group=group_id, domains=changed)
    return changed
