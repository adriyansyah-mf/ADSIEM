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

from app.models.models import (
    Agent, Alert, AlertNote, Case, CaseNote, FimEvent, HygieneSnapshot,
    Rule, ThreatHunt, UebaAnomaly, UebaEntityScore, YaraRule,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Models frequently send a semantically-equivalent key instead of the exact
# schema property name (observed: 'indicator' for 'ioc', 'entity' for 'value').
# Accept aliases so a correct call is not rejected on a naming mismatch.
_ARG_ALIASES = {
    "ioc": ("ioc", "indicator", "value", "ip", "hostname"),
    "value": ("value", "entity", "indicator", "ioc", "ip", "hostname"),
    "hours": ("hours", "lookback_hours", "window_hours", "window", "hours_back"),
    "case_id": ("case_id", "case", "id"),
}


def _arg(args: dict, key: str, default=None):
    for alias in _ARG_ALIASES.get(key, (key,)):
        if alias in args and args[alias] not in (None, ""):
            return args[alias]
    return default

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
        "name": "correlate_entity",
        "description": (
            "Correlate one indicator (IP or hostname) across agents within a time window — "
            "how many alerts, which hosts, which rules, which MITRE techniques. Use this to "
            "tell whether activity is isolated to one host or spread laterally."
        ),
        "parameters": {
            "value": "IP address or hostname to correlate (required)",
            "hours": "lookback window in hours, default 24, max 720",
        },
        "schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "IP address or hostname to correlate"},
                "hours": {"type": "integer", "description": "lookback window in hours (default 24, max 720)"},
            },
            "required": ["value"],
        },
    },
    {
        "name": "reconstruct_timeline",
        "description": (
            "Build a chronological timeline for an entity or case: alerts, case notes and FIM "
            "changes interleaved by time. Use this to explain the sequence of an intrusion."
        ),
        "parameters": {
            "value": "IP or hostname (optional if case_id given)",
            "case_id": "case UUID (optional if value given)",
            "hours": "lookback window in hours, default 48, max 720",
        },
        "schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "IP or hostname"},
                "case_id": {"type": "string", "description": "case UUID"},
                "hours": {"type": "integer", "description": "lookback window in hours (default 48, max 720)"},
            },
            "required": [],
        },
    },
    {
        "name": "pivot_ioc",
        "description": (
            "Pivot on an indicator: related alerts, cases referencing it, and UEBA risk score. "
            "Use this to expand an investigation from one IOC to everything it touches."
        ),
        "parameters": {
            "ioc": "the indicator value (IP, hostname) to pivot on (required)",
        },
        "schema": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "indicator value (IP or hostname)"},
            },
            "required": ["ioc"],
        },
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

    if name == "correlate_entity":
        value = str(_arg(args, "value") or "").strip()
        if not value:
            return {"error": "value is required"}
        hours = clamp(_arg(args, "hours"), 24, 720)
        since = _now() - timedelta(hours=hours)
        q = select(Alert).where(
            Alert.created_at >= since,
            or_(Alert.source_ip == value, Alert.hostname == value),
        )
        if group_filter:
            q = q.where(Alert.group_id == group_filter)
        rows = (await db.execute(q.order_by(Alert.created_at.asc()).limit(200))).scalars().all()

        hosts = sorted({a.hostname for a in rows if a.hostname})
        rules = sorted({a.title for a in rows if a.title})
        techniques = sorted({t for a in rows for t in (a.mitre_techniques or [])})
        return {
            "value": value,
            "window_hours": hours,
            "alert_count": len(rows),
            "distinct_hosts": len(hosts),
            "hosts": hosts[:25],
            "top_rules": rules[:15],
            "mitre_techniques": techniques[:25],
            "spread_assessment": (
                "single_host" if len(hosts) <= 1 else f"spread_across_{len(hosts)}_hosts"
            ),
        }

    if name == "reconstruct_timeline":
        hours = clamp(_arg(args, "hours"), 48, 720)
        since = _now() - timedelta(hours=hours)
        value = str(_arg(args, "value") or "").strip()
        case_id = _arg(args, "case_id")

        if not value and not case_id:
            return {"error": "provide value or case_id"}

        entity_filter = None
        if case_id:
            try:
                case = await db.get(Case, UUID(str(case_id)))
            except (ValueError, TypeError):
                return {"error": "invalid case_id"}
            if not case or (group_filter and case.group_id != group_filter):
                return {"error": "not found"}
            entity_filter = case.alert_id
            if not value and case.alert_id:
                trigger = await db.get(Alert, case.alert_id)
                if trigger:
                    value = trigger.source_ip or trigger.hostname or value

        items: list[dict] = []

        aq = select(Alert).where(Alert.created_at >= since)
        if group_filter:
            aq = aq.where(Alert.group_id == group_filter)
        if entity_filter:
            aq = aq.where(Alert.id == entity_filter)
        elif value:
            aq = aq.where(or_(Alert.source_ip == value, Alert.hostname == value))
        for a in (await db.execute(aq.order_by(Alert.created_at.asc()).limit(100))).scalars().all():
            items.append({
                "ts": a.created_at.isoformat(), "type": "alert",
                "title": a.title, "severity": a.severity, "hostname": a.hostname,
            })

        fq = select(FimEvent).where(FimEvent.detected_at >= since)
        if group_filter:
            fq = fq.where(FimEvent.group_id == group_filter)
        if value:
            fq = fq.where(FimEvent.path.ilike(f"%{value}%"))
        for f in (await db.execute(fq.order_by(FimEvent.detected_at.asc()).limit(50))).scalars().all():
            items.append({
                "ts": f.detected_at.isoformat(), "type": "fim",
                "title": f"{f.event_type} {f.path}", "hostname": None,
            })

        items.sort(key=lambda x: x["ts"])
        return {"entity": value, "window_hours": hours, "event_count": len(items), "timeline": items[:150]}

    if name == "pivot_ioc":
        ioc = str(_arg(args, "ioc") or "").strip()
        if not ioc:
            return {"error": "ioc is required"}

        aq = select(Alert).where(or_(Alert.source_ip == ioc, Alert.hostname == ioc))
        if group_filter:
            aq = aq.where(Alert.group_id == group_filter)
        alerts = (await db.execute(aq.order_by(Alert.created_at.desc()).limit(50))).scalars().all()

        cq = select(Case).where(Case.title.ilike(f"%{ioc}%"))
        if group_filter:
            cq = cq.where(Case.group_id == group_filter)
        title_cases = (await db.execute(cq.order_by(Case.created_at.desc()).limit(25))).scalars().all()

        linked_ids = [a.id for a in alerts[:50]]
        alert_cases = []
        if linked_ids:
            acq = select(Case).where(Case.alert_id.in_(linked_ids))
            if group_filter:
                acq = acq.where(Case.group_id == group_filter)
            alert_cases = (await db.execute(
                acq.order_by(Case.created_at.desc()).limit(25)
            )).scalars().all()

        seen: set = set()
        cases = []
        for c in list(title_cases) + list(alert_cases):
            if c.id not in seen:
                seen.add(c.id)
                cases.append(c)

        risk = 0.0
        try:
            row = await db.get(UebaEntityScore, ("ip", ioc))
            if row and (not group_filter or row.group_id == group_filter):
                risk = float(row.risk_score or 0.0)
        except Exception:
            pass

        return {
            "ioc": ioc,
            "alert_count": len(alerts),
            "case_count": len(cases),
            "ueba_risk_score": risk,
            "alerts": [
                {"id": str(a.id), "title": a.title, "severity": a.severity,
                 "status": a.status, "created_at": a.created_at.isoformat()}
                for a in alerts[:25]
            ],
            "cases": [
                {"id": str(c.id), "title": c.title, "status": c.status,
                 "created_at": c.created_at.isoformat()}
                for c in cases[:15]
            ],
        }

    return {"error": f"unknown tool: {name}"}
