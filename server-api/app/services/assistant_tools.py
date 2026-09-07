# server-api/app/services/assistant_tools.py
"""Read-only tools the SOC chat assistant can call. Deliberately excludes
settings, users, and webhooks — those modules are never imported or queried
here, so there is no code path for the assistant to reach them even if a
prompt tried to talk it into it."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre_tactics import TACTIC_ORDER, parse_technique, tactic_for_code
from app.models.models import (
    Agent, Alert, AlertNote, AuditLog, Case, CaseNote, FimEvent, HygieneSnapshot,
    IocLink, IocObservation, Rule, ThreatHunt, UebaAnomaly, UebaEntityScore, YaraRule,
)

TOOLS: list[dict] = [
    {
        "name": "search_alerts",
        "description": "Search/list alerts. Any filter may be omitted.",
        "parameters": {
            "status": "new|acknowledged|closed|resolved (optional)",
            "severity": "info|low|medium|high|critical (optional)",
            "hostname": "exact or partial hostname (optional)",
            "source_ip": "exact source IP (optional)",
            "limit": "max results, default 10, max 25",
        },
    },
    {"name": "get_alert", "description": "Get one alert by id, including its analyst/AI notes.",
     "parameters": {"alert_id": "UUID string, required"}},
    {
        "name": "search_cases",
        "description": "Search/list cases (investigations).",
        "parameters": {
            "status": "open|in_review|escalated|resolved|closed (optional)",
            "severity": "info|low|medium|high|critical (optional)",
            "limit": "max results, default 10, max 25",
        },
    },
    {"name": "get_case", "description": "Get one case by id, including its notes and AI reasoning.",
     "parameters": {"case_id": "UUID string, required"}},
    {
        "name": "list_agents",
        "description": "List enrolled agents (endpoints) and their online/offline status.",
        "parameters": {"status": "online|offline (optional)", "limit": "default 20, max 50"},
    },
    {
        "name": "ueba_top_risky_entities",
        "description": "Top IPs/hosts by UEBA risk score, and recent behavioral anomalies.",
        "parameters": {"limit": "default 10, max 25"},
    },
    {
        "name": "recent_fim_changes",
        "description": "Recent File Integrity Monitoring changes (created/modified/deleted files).",
        "parameters": {"hostname": "optional", "limit": "default 15, max 30"},
    },
    {
        "name": "agent_hygiene",
        "description": "Latest system hygiene snapshot for an agent — OS, patch/uptime, open ports, disk usage.",
        "parameters": {"hostname": "required"},
    },
    {
        "name": "list_threat_hunts",
        "description": "List threat hunts (IOC sweeps) and their status/results.",
        "parameters": {"limit": "default 10, max 25"},
    },
    {
        "name": "search_rules",
        "description": "Search detection rules by title/keyword.",
        "parameters": {"query": "keyword to search rule titles/descriptions", "limit": "default 10, max 25"},
    },
    {
        "name": "yara_rule_status",
        "description": "List YARA rules and whether each is enabled.",
        "parameters": {"limit": "default 20, max 50"},
    },
    {
        "name": "dashboard_stats",
        "description": "Overall counts: alerts by severity/status, open cases, online agents. Good first call for broad questions.",
        "parameters": {},
    },
    {
        "name": "entity_pivot",
        "description": "Everything known about one IP, hostname, or UEBA-tracked entity: its alerts, cases, UEBA risk score, and behavioral anomalies.",
        "parameters": {"entity_type": "ip|hostname|user|... required", "entity_value": "the IP/hostname/username itself, required"},
    },
    {
        "name": "ioc_lookup",
        "description": "Threat-intel pivot for one indicator (IP, domain, hash, or URL): every observation (source, confidence, verdict) and what it's been linked to.",
        "parameters": {"indicator": "the IP/domain/hash/URL to look up, required"},
    },
    {
        "name": "mitre_technique_coverage",
        "description": "Which MITRE ATT&CK techniques have actually fired, ranked by frequency, over a recent period. Good for 'what techniques are we seeing' questions.",
        "parameters": {"days": "lookback window, default 30, max 365", "limit": "max techniques returned, default 10, max 25"},
    },
    {
        "name": "recent_audit_log",
        "description": "Recent platform audit trail — who did what (logins, settings changes, rule edits, etc.) and when. No access to the raw event detail payload.",
        "parameters": {"action": "filter by action name, e.g. login_success (optional)", "limit": "default 15, max 30"},
    },
]


def _severity_ok(v: Any) -> bool:
    return isinstance(v, str) and v.lower() in ("info", "low", "medium", "high", "critical")


async def run_tool(name: str, args: dict, db: AsyncSession, group_filter: str | None) -> dict:
    args = args or {}
    limit_cap = 25

    def clamp(v, default, cap):
        try:
            n = int(v)
        except (TypeError, ValueError):
            return default
        return max(1, min(n, cap))

    if name == "search_alerts":
        q = select(Alert)
        if group_filter:
            q = q.where(Alert.group_id == group_filter)
        if args.get("status"):
            q = q.where(Alert.status == args["status"])
        if _severity_ok(args.get("severity")):
            q = q.where(Alert.severity == args["severity"].lower())
        if args.get("hostname"):
            q = q.where(Alert.hostname.ilike(f"%{args['hostname']}%"))
        if args.get("source_ip"):
            q = q.where(Alert.source_ip == args["source_ip"])
        q = q.order_by(Alert.created_at.desc()).limit(clamp(args.get("limit"), 10, limit_cap))
        rows = (await db.execute(q)).scalars().all()
        return {"alerts": [
            {"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status,
             "hostname": a.hostname, "source_ip": a.source_ip, "created_at": a.created_at.isoformat()}
            for a in rows
        ]}

    if name == "get_alert":
        try:
            a = await db.get(Alert, UUID(str(args.get("alert_id"))))
        except (ValueError, TypeError):
            return {"error": "invalid alert_id"}
        if not a or (group_filter and a.group_id != group_filter):
            return {"error": "not found"}
        notes = (await db.execute(
            select(AlertNote).where(AlertNote.alert_id == a.id).order_by(AlertNote.created_at.asc())
        )).scalars().all()
        return {
            "id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status,
            "hostname": a.hostname, "source_ip": a.source_ip, "created_at": a.created_at.isoformat(),
            "notes": [{"content": n.content[:1500], "created_at": n.created_at.isoformat()} for n in notes],
        }

    if name == "search_cases":
        q = select(Case)
        if group_filter:
            q = q.where(Case.group_id == group_filter)
        if args.get("status"):
            q = q.where(Case.status == args["status"])
        if _severity_ok(args.get("severity")):
            q = q.where(Case.severity == args["severity"].lower())
        q = q.order_by(Case.created_at.desc()).limit(clamp(args.get("limit"), 10, limit_cap))
        rows = (await db.execute(q)).scalars().all()
        return {"cases": [
            {"id": str(c.id), "title": c.title, "severity": c.severity, "status": c.status,
             "created_by_ai": c.created_by_ai, "created_at": c.created_at.isoformat()}
            for c in rows
        ]}

    if name == "get_case":
        try:
            c = await db.get(Case, UUID(str(args.get("case_id"))))
        except (ValueError, TypeError):
            return {"error": "invalid case_id"}
        if not c or (group_filter and c.group_id != group_filter):
            return {"error": "not found"}
        notes = (await db.execute(
            select(CaseNote).where(CaseNote.case_id == c.id).order_by(CaseNote.created_at.asc())
        )).scalars().all()
        return {
            "id": str(c.id), "title": c.title, "severity": c.severity, "status": c.status,
            "ai_reasoning": (c.ai_reasoning or "")[:1500], "ai_confidence": c.ai_confidence,
            "created_at": c.created_at.isoformat(),
            "notes": [{"content": n.content[:1500], "created_at": n.created_at.isoformat()} for n in notes],
        }

    if name == "list_agents":
        q = select(Agent)
        if group_filter:
            q = q.where(Agent.group_id == group_filter)
        if args.get("status"):
            q = q.where(Agent.status == args["status"])
        q = q.order_by(Agent.hostname.asc()).limit(clamp(args.get("limit"), 20, 50))
        rows = (await db.execute(q)).scalars().all()
        return {"agents": [
            {"name": a.name, "hostname": a.hostname, "status": a.status,
             "is_isolated": a.is_isolated, "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None}
            for a in rows
        ]}

    if name == "ueba_top_risky_entities":
        q = select(UebaEntityScore)
        if group_filter:
            q = q.where(UebaEntityScore.group_id == group_filter)
        q = q.order_by(UebaEntityScore.risk_score.desc()).limit(clamp(args.get("limit"), 10, limit_cap))
        rows = (await db.execute(q)).scalars().all()
        return {"entities": [
            {"type": e.entity_type, "value": e.entity_value, "risk_score": e.risk_score,
             "anomaly_count": e.anomaly_count}
            for e in rows
        ]}

    if name == "recent_fim_changes":
        q = select(FimEvent)
        if group_filter:
            q = q.where(FimEvent.group_id == group_filter)
        if args.get("hostname"):
            q = q.join(Agent, Agent.id == FimEvent.agent_id).where(Agent.hostname.ilike(f"%{args['hostname']}%"))
        q = q.order_by(FimEvent.detected_at.desc()).limit(clamp(args.get("limit"), 15, 30))
        rows = (await db.execute(q)).scalars().all()
        return {"fim_events": [
            {"path": f.path, "event_type": f.event_type, "sha256": f.sha256,
             "detected_at": f.detected_at.isoformat()}
            for f in rows
        ]}

    if name == "agent_hygiene":
        if not args.get("hostname"):
            return {"error": "hostname is required"}
        q = select(HygieneSnapshot).where(HygieneSnapshot.hostname.ilike(f"%{args['hostname']}%"))
        if group_filter:
            q = q.where(HygieneSnapshot.group_id == group_filter)
        q = q.order_by(HygieneSnapshot.collected_at.desc()).limit(1)
        h = (await db.execute(q)).scalar_one_or_none()
        if not h:
            return {"error": "no hygiene snapshot found for that hostname"}
        return {
            "hostname": h.hostname, "os": f"{h.os_name} {h.os_version}", "kernel": h.kernel,
            "arch": h.arch, "uptime_seconds": h.uptime_seconds, "cpu_count": h.cpu_count,
            "mem_used_mb": h.mem_used_mb, "mem_total_mb": h.mem_total_mb,
            "open_ports": h.open_ports, "disk_partitions": h.disk_partitions,
        }

    if name == "list_threat_hunts":
        q = select(ThreatHunt)
        if group_filter:
            q = q.where(ThreatHunt.group_id == group_filter)
        q = q.order_by(ThreatHunt.created_at.desc()).limit(clamp(args.get("limit"), 10, limit_cap))
        rows = (await db.execute(q)).scalars().all()
        return {"hunts": [
            {"ioc_type": h.ioc_type, "ioc_value": h.ioc_value, "status": h.status,
             "risk_level": h.risk_level, "alert_count": h.alert_count, "event_count": h.event_count,
             "created_at": h.created_at.isoformat()}
            for h in rows
        ]}

    if name == "search_rules":
        q = select(Rule)
        if group_filter:
            q = q.where(or_(Rule.group_id == group_filter, Rule.group_id.is_(None)))
        if args.get("query"):
            like = f"%{args['query']}%"
            q = q.where(or_(Rule.title.ilike(like), Rule.description.ilike(like)))
        q = q.order_by(Rule.title.asc()).limit(clamp(args.get("limit"), 10, limit_cap))
        rows = (await db.execute(q)).scalars().all()
        return {"rules": [
            {"title": r.title, "level": r.level, "is_enabled": r.is_enabled, "tags": r.tags}
            for r in rows
        ]}

    if name == "yara_rule_status":
        q = select(YaraRule).order_by(YaraRule.name.asc()).limit(clamp(args.get("limit"), 20, 50))
        rows = (await db.execute(q)).scalars().all()
        return {"yara_rules": [{"name": y.name, "is_enabled": y.is_enabled} for y in rows]}

    if name == "dashboard_stats":
        alert_q = select(Alert.severity, func.count()).group_by(Alert.severity)
        case_q = select(func.count()).select_from(Case).where(Case.status.in_(["open", "in_review", "escalated"]))
        agent_q = select(func.count()).select_from(Agent).where(Agent.status == "online")
        if group_filter:
            alert_q = alert_q.where(Alert.group_id == group_filter)
            case_q = case_q.where(Case.group_id == group_filter)
            agent_q = agent_q.where(Agent.group_id == group_filter)
        sev_rows = (await db.execute(alert_q)).all()
        open_cases = (await db.execute(case_q)).scalar_one()
        online_agents = (await db.execute(agent_q)).scalar_one()
        return {
            "alerts_by_severity": {s: c for s, c in sev_rows},
            "open_cases": open_cases,
            "online_agents": online_agents,
        }

    if name == "entity_pivot":
        entity_type = args.get("entity_type")
        entity_value = args.get("entity_value")
        if not entity_type or not entity_value:
            return {"error": "entity_type and entity_value are required"}

        alert_match_columns = {"ip": Alert.source_ip, "hostname": Alert.hostname}
        alerts: list[Alert] = []
        match_column = alert_match_columns.get(entity_type)
        if match_column is not None:
            q = select(Alert).where(match_column == entity_value)
            if group_filter:
                q = q.where(Alert.group_id == group_filter)
            alerts = (await db.execute(q.order_by(Alert.created_at.desc()).limit(20))).scalars().all()

        cases: list[Case] = []
        if alerts:
            q = select(Case).where(Case.alert_id.in_([a.id for a in alerts]))
            if group_filter:
                q = q.where(Case.group_id == group_filter)
            cases = (await db.execute(q)).scalars().all()

        score_q = select(UebaEntityScore).where(
            UebaEntityScore.entity_type == entity_type, UebaEntityScore.entity_value == entity_value)
        if group_filter:
            score_q = score_q.where(UebaEntityScore.group_id == group_filter)
        score = (await db.execute(score_q)).scalar_one_or_none()

        anomaly_q = select(UebaAnomaly).where(
            UebaAnomaly.entity_type == entity_type, UebaAnomaly.entity_value == entity_value)
        if group_filter:
            anomaly_q = anomaly_q.where(UebaAnomaly.group_id == group_filter)
        anomalies = (await db.execute(
            anomaly_q.order_by(UebaAnomaly.detected_at.desc()).limit(10)
        )).scalars().all()

        if not alerts and not cases and score is None and not anomalies:
            return {"error": "no data found for that entity"}
        return {
            "entity_type": entity_type, "entity_value": entity_value,
            "risk_score": score.risk_score if score else None,
            "anomaly_count": score.anomaly_count if score else 0,
            "alerts": [{"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status,
                        "created_at": a.created_at.isoformat()} for a in alerts],
            "cases": [{"id": str(c.id), "title": c.title, "status": c.status} for c in cases],
            "anomalies": [{"anomaly_score": a.anomaly_score, "ai_narrative": (a.ai_narrative or "")[:500],
                           "detected_at": a.detected_at.isoformat() if a.detected_at else None} for a in anomalies],
        }

    if name == "ioc_lookup":
        indicator = args.get("indicator")
        if not indicator:
            return {"error": "indicator is required"}
        q = select(IocObservation).where(IocObservation.indicator == indicator)
        if group_filter:
            q = q.where(IocObservation.group_id == group_filter)
        observations = (await db.execute(q)).scalars().all()
        if not observations:
            return {"error": "no observations found for that indicator"}
        link_q = select(IocLink).where(IocLink.ioc_id.in_([o.id for o in observations]))
        if group_filter:
            link_q = link_q.where(IocLink.group_id == group_filter)
        links = (await db.execute(link_q)).scalars().all()
        return {
            "indicator": indicator,
            "observations": [
                {"ioc_type": o.ioc_type, "confidence": o.confidence, "verdict": o.verdict, "source": o.source,
                 "first_seen": o.first_seen.isoformat() if o.first_seen else None,
                 "last_seen": o.last_seen.isoformat() if o.last_seen else None}
                for o in observations
            ],
            "linked_to": [{"entity_type": l.entity_type, "entity_id": l.entity_id} for l in links],
        }

    if name == "mitre_technique_coverage":
        since = datetime.now(timezone.utc) - timedelta(days=clamp(args.get("days"), 30, 365))
        q = select(Alert.mitre_techniques).where(Alert.created_at >= since, Alert.mitre_techniques != [])
        if group_filter:
            q = q.where(Alert.group_id == group_filter)
        rows = (await db.execute(q)).scalars().all()
        counts: dict[str, dict] = {}
        for techniques in rows:
            for entry in techniques or []:
                code, tname = parse_technique(entry)
                tactic = tactic_for_code(code)
                if tactic == "Unknown":
                    continue
                slot = counts.setdefault(code, {"technique_id": code, "technique_name": tname, "tactic": tactic, "count": 0})
                slot["count"] += 1
        top = sorted(counts.values(), key=lambda e: e["count"], reverse=True)[:clamp(args.get("limit"), 10, limit_cap)]
        return {"period_days": clamp(args.get("days"), 30, 365), "top_techniques": top}

    if name == "recent_audit_log":
        q = select(AuditLog)
        if group_filter:
            q = q.where(AuditLog.group_id == group_filter)
        if args.get("action"):
            q = q.where(AuditLog.action == args["action"])
        q = q.order_by(AuditLog.created_at.desc()).limit(clamp(args.get("limit"), 15, 30))
        rows = (await db.execute(q)).scalars().all()
        return {"audit_entries": [
            {"action": e.action, "actor_type": e.actor_type, "resource_type": e.resource_type,
             "resource_id": e.resource_id, "created_at": e.created_at.isoformat() if e.created_at else None}
            for e in rows
        ]}

    return {"error": f"unknown tool: {name}"}
