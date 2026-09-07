# server-api/app/services/compliance.py
"""Compliance Manager — evaluates each enrolled ENDPOINT (a host running the
siem-agent) against commonly-cited control references (ISO/IEC 27001,
PCI-DSS, SOC 2), using real data that agent already reports: hygiene
snapshots (OS/package/user/port/disk info), FIM events, and fleet-health
heartbeat telemetry (P0-B). This is an internal posture tracker per host, not
a certified audit deliverable: every status is derived from an actual query
below, never hardcoded or guessed. A control this platform genuinely cannot
evidence yet reports "not_automated" rather than a fabricated status.

Several controls across frameworks share the same underlying fact (e.g.
hygiene score backs ISO A.12.6, PCI 6.3, and SOC2 CC3.2 simultaneously) —
CHECKS is the single source of truth per fact, FRAMEWORKS just cites it under
each framework's own control numbering."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Agent, HygieneSnapshot, FimWatchPath, FimEvent

CheckResult = dict  # {"status": "met" | "partial" | "gap" | "not_automated", "evidence": str}

# Well-known insecure/legacy network services — if listening, that's a real,
# well-established hardening gap (not a heuristic guess).
_INSECURE_PORTS = {21: "FTP (unencrypted)", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh", 6000: "X11"}


async def _latest_snapshot(db: AsyncSession, agent_id: str) -> HygieneSnapshot | None:
    q = (
        select(HygieneSnapshot)
        .where(HygieneSnapshot.agent_id == agent_id)
        .order_by(HygieneSnapshot.collected_at.desc())
        .limit(1)
    )
    return (await db.execute(q)).scalar_one_or_none()


async def _check_hygiene_posture(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No hygiene snapshot collected yet from this host."}
    status = "met" if snap.hygiene_score >= 80 else ("partial" if snap.hygiene_score >= 50 else "gap")
    age_h = round((datetime.now(timezone.utc) - snap.collected_at).total_seconds() / 3600, 1)
    return {"status": status, "evidence": f"Hygiene score {snap.hygiene_score}/100, {len(snap.issues)} open issue(s) (snapshot {age_h}h old)."}


async def _check_open_ports_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No open-port data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "network")
    if aggregated is not None:
        return aggregated
    if snap.open_ports is None:
        return {"status": "not_automated", "evidence": "No open-port data collected yet from this host."}
    found = []
    for p in snap.open_ports:
        port = p.get("port") if isinstance(p, dict) else None
        if port in _INSECURE_PORTS and (p.get("state") or "").lower() in ("listen", "listening", "open"):
            found.append(f"{port}/{_INSECURE_PORTS[port]}")
    if found:
        return {"status": "gap", "evidence": f"Legacy/insecure service(s) listening: {', '.join(found)}."}
    return {"status": "met", "evidence": f"No legacy/insecure services (FTP, Telnet, r-commands, X11) found among {len(snap.open_ports)} open port(s)."}


def _aggregate_hardening_category(snap: HygieneSnapshot, category: str) -> CheckResult | None:
    """Aggregate all agent-reported hardening checks in one category into a
    single control status. Returns None if this host hasn't reported any
    hardening data yet for this category — callers fall back to older,
    shallower logic so hosts on a not-yet-upgraded agent don't regress."""
    checks = [c for c in (snap.hardening_checks or []) if c.get("category") == category]
    if not checks:
        return None
    applicable = [c for c in checks if c.get("status") != "not_applicable"]
    if not applicable:
        return {"status": "not_automated", "evidence": f"All {len(checks)} {category} check(s) reported not_applicable on this host."}
    failed = [c for c in applicable if c.get("status") == "fail"]
    errored = [c for c in applicable if c.get("status") == "error"]
    passed = [c for c in applicable if c.get("status") == "pass"]
    if not failed and not errored:
        return {"status": "met", "evidence": f"All {len(passed)} applicable {category} hardening check(s) pass."}
    failed_titles = ", ".join(c.get("title", c.get("id", "?")) for c in failed)
    errored_titles = ", ".join(c.get("title", c.get("id", "?")) for c in errored)
    if failed and errored:
        status = "gap" if not passed else "partial"
        return {"status": status, "evidence": f"{len(passed)}/{len(applicable)} {category} check(s) pass. "
                                                f"Failing: {failed_titles}. Could not be evaluated: {errored_titles}."}
    if errored:
        # No outright failures — just checks we couldn't evaluate (e.g. a
        # privileged read denied to the agent's service account). "We don't
        # know" is not the same as "it's bad", so this can't be a gap.
        return {"status": "partial", "evidence": f"{len(passed)}/{len(applicable)} {category} check(s) pass. "
                                                   f"Could not be evaluated: {errored_titles}."}
    if passed:
        return {"status": "partial", "evidence": f"{len(passed)}/{len(applicable)} {category} check(s) pass. Failing: {failed_titles}."}
    return {"status": "gap", "evidence": f"All {len(applicable)} {category} hardening check(s) fail: {failed_titles}."}


async def _check_disk_capacity(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap or not snap.disk_partitions:
        return {"status": "not_automated", "evidence": "No disk usage data collected yet from this host."}
    worst = max(snap.disk_partitions, key=lambda p: p.get("use_pct", 0))
    pct = round(worst.get("use_pct", 0), 1)
    status = "met" if pct < 85 else ("partial" if pct < 95 else "gap")
    return {"status": status, "evidence": f"Highest partition usage: {worst.get('mount', '?')} at {pct}% "
                                           f"(of {len(snap.disk_partitions)} partition(s))."}


async def _check_capacity_monitoring(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap or not snap.mem_total_mb:
        return {"status": "not_automated", "evidence": "No memory usage data collected yet from this host."}
    pct = round((snap.mem_used_mb or 0) / snap.mem_total_mb * 100, 1)
    status = "met" if pct < 85 else ("partial" if pct < 95 else "gap")
    return {"status": status, "evidence": f"Memory usage {snap.mem_used_mb}/{snap.mem_total_mb} MB ({pct}%)."}


async def _check_agent_monitoring_health(db: AsyncSession, agent_id: str) -> CheckResult:
    agent = await db.get(Agent, agent_id)
    if not agent:
        return {"status": "not_automated", "evidence": "Agent record not found."}
    if agent.status != "online":
        last_seen = agent.last_seen_at.isoformat() if agent.last_seen_at else "never"
        return {"status": "gap", "evidence": f"Host is offline (last seen {last_seen}) — not currently reporting security events."}
    degraded = (agent.oldest_buffered_event_age_seconds or 0) > 60 or (agent.buffer_depth or 0) > 0
    if degraded:
        return {"status": "partial", "evidence": f"Online but event buffer is backed up (depth={agent.buffer_depth}, "
                                                   f"oldest queued {agent.oldest_buffered_event_age_seconds}s) — events may be delayed."}
    return {"status": "met", "evidence": f"Online and forwarding events in real time (uptime {round((agent.uptime_seconds or 0) / 3600, 1)}h)."}


async def _check_file_integrity_monitoring(db: AsyncSession, agent_id: str) -> CheckResult:
    paths = (await db.execute(select(FimWatchPath).where(FimWatchPath.is_enabled.is_(True)))).scalars().all()
    if not paths:
        return {"status": "gap", "evidence": "No file-integrity-monitoring watch paths configured platform-wide."}
    since = datetime.now(timezone.utc) - timedelta(days=30)
    count = (await db.execute(
        select(func.count()).select_from(FimEvent).where(FimEvent.agent_id == agent_id, FimEvent.detected_at >= since)
    )).scalar_one()
    return {"status": "met", "evidence": f"{len(paths)} watch path(s) configured platform-wide; "
                                          f"{count} file-integrity event(s) detected on this host in last 30 days."}


async def _check_local_account_hygiene(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No local account data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "account")
    if aggregated is not None:
        return aggregated
    # Fall back to the shallow UID-0 check for hosts on an older agent
    # version that hasn't reported hardening_checks yet.
    if snap.users is None:
        return {"status": "not_automated", "evidence": "No local account data collected yet from this host."}
    users = snap.users
    root_uid0 = [u.get("name") for u in users if u.get("uid") == 0]
    extra_root = [n for n in root_uid0 if n != "root"]
    interactive = [u for u in users if u.get("shell", "") not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "")]
    if extra_root:
        return {"status": "gap", "evidence": f"Non-root account(s) with UID 0 (root-equivalent): {', '.join(extra_root)}."}
    return {"status": "met", "evidence": f"{len(interactive)} local account(s) with an interactive shell; no unauthorized UID-0 accounts."}


async def _check_ssh_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No SSH hardening data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "ssh")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported SSH hardening checks yet (requires an agent update)."}


async def _check_kernel_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No kernel hardening data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "kernel")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported kernel hardening checks yet (requires an agent update)."}


async def _check_logging_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No logging hardening data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "logging")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported logging hardening checks yet (requires an agent update)."}


async def _check_update_management(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No update-management data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "updates")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported update-management checks yet (requires an agent update)."}


CHECKS: dict[str, Callable[[AsyncSession, str], Awaitable[CheckResult]]] = {
    "hygiene_posture": _check_hygiene_posture,
    "open_ports_hardening": _check_open_ports_hardening,
    "disk_capacity": _check_disk_capacity,
    "capacity_monitoring": _check_capacity_monitoring,
    "agent_monitoring_health": _check_agent_monitoring_health,
    "file_integrity_monitoring": _check_file_integrity_monitoring,
    "local_account_hygiene": _check_local_account_hygiene,
    "ssh_hardening": _check_ssh_hardening,
    "kernel_hardening": _check_kernel_hardening,
    "logging_hardening": _check_logging_hardening,
    "update_management": _check_update_management,
}

FRAMEWORKS: dict[str, dict] = {
    "iso27001": {
        "name": "ISO/IEC 27001:2022 (Annex A)",
        "controls": [
            {"id": "A.12.6", "title": "Technical vulnerability management", "check": "hygiene_posture"},
            {"id": "A.13.1", "title": "Network security management", "check": "open_ports_hardening"},
            {"id": "A.12.1.3", "title": "Capacity management", "check": "disk_capacity"},
            {"id": "A.12.4", "title": "Logging and monitoring of this asset", "check": "agent_monitoring_health"},
            {"id": "A.12.4.1", "title": "Detection of unauthorized file changes", "check": "file_integrity_monitoring"},
            {"id": "A.9.2.5", "title": "Review of local user access rights", "check": "local_account_hygiene"},
            {"id": "A.8.20", "title": "SSH remote access hardening", "check": "ssh_hardening"},
            {"id": "A.8.9", "title": "Configuration hardening (kernel/filesystem)", "check": "kernel_hardening"},
            {"id": "A.8.15", "title": "Event logging (auditd, time synchronization)", "check": "logging_hardening"},
            {"id": "A.8.8", "title": "Management of technical vulnerabilities (patch automation)", "check": "update_management"},
            {"id": "A.8.6", "title": "Capacity management (memory)", "check": "capacity_monitoring"},
        ],
    },
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "controls": [
            {"id": "Req 6.3", "title": "Identify and address security vulnerabilities", "check": "hygiene_posture"},
            {"id": "Req 2.2.2", "title": "Disable/remove unnecessary insecure services", "check": "open_ports_hardening"},
            {"id": "Req 10.5.1", "title": "Protect audit log storage capacity", "check": "disk_capacity"},
            {"id": "Req 10.7", "title": "Failures of critical security control systems are detected", "check": "agent_monitoring_health"},
            {"id": "Req 11.5", "title": "Deploy a change/file-integrity detection mechanism", "check": "file_integrity_monitoring"},
            {"id": "Req 7.2", "title": "Unique accounts, no shared/root-equivalent access", "check": "local_account_hygiene"},
            {"id": "Req 2.2.7", "title": "Secure remote administrative access (SSH hardening)", "check": "ssh_hardening"},
            {"id": "Req 2.2", "title": "System configuration hardening", "check": "kernel_hardening"},
            {"id": "Req 10.6", "title": "Time-synchronization mechanisms and audit logging active", "check": "logging_hardening"},
            {"id": "Req 6.3.3", "title": "Security patches installed/automated within defined timelines", "check": "update_management"},
            {"id": "Req 10.5.2", "title": "System resource capacity is monitored", "check": "capacity_monitoring"},
        ],
    },
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria)",
        "controls": [
            {"id": "CC3.2", "title": "Risk assessment identifies vulnerabilities", "check": "hygiene_posture"},
            {"id": "CC6.6", "title": "Restricts unnecessary network services", "check": "open_ports_hardening"},
            {"id": "A1.1", "title": "Capacity is monitored to meet availability commitments", "check": "disk_capacity"},
            {"id": "CC7.2", "title": "Monitors system components for anomalies", "check": "agent_monitoring_health"},
            {"id": "CC7.1", "title": "Detects unauthorized changes to configurations/files", "check": "file_integrity_monitoring"},
            {"id": "CC6.2", "title": "Periodic review of provisioned local accounts", "check": "local_account_hygiene"},
            {"id": "CC6.1b", "title": "Secure remote access configuration", "check": "ssh_hardening"},
            {"id": "CC6.8", "title": "Prevents/detects unauthorized software and configuration changes", "check": "kernel_hardening"},
            {"id": "CC7.2c", "title": "Logging and time synchronization support anomaly detection", "check": "logging_hardening"},
            {"id": "CC3.4", "title": "Identified deficiencies (missing patches) are remediated", "check": "update_management"},
            {"id": "A1.2", "title": "Environmental/resource capacity is monitored", "check": "capacity_monitoring"},
        ],
    },
}


async def list_endpoints(db: AsyncSession, group_filter: str | None) -> list[dict]:
    q = select(Agent)
    if group_filter:
        q = q.where(Agent.group_id == group_filter)
    q = q.order_by(Agent.name)
    agents = (await db.execute(q)).scalars().all()
    return [{"id": str(a.id), "name": a.name, "hostname": a.hostname, "status": a.status} for a in agents]


async def evaluate_endpoint_framework(db: AsyncSession, agent_id: str, framework_id: str) -> dict:
    fw = FRAMEWORKS[framework_id]
    cache: dict[str, CheckResult] = {}
    controls = []
    for c in fw["controls"]:
        check_key = c["check"]
        if check_key not in cache:
            cache[check_key] = await CHECKS[check_key](db, agent_id)
        controls.append({**c, **cache[check_key]})
    scorable = [c for c in controls if c["status"] != "not_automated"]
    met = sum(1 for c in scorable if c["status"] == "met")
    total = len(controls)
    return {
        "id": framework_id,
        "name": fw["name"],
        "agent_id": agent_id,
        "controls": controls,
        "met_count": met,
        "total_count": total,
        # Scored only against controls this host can actually be evaluated
        # on — a not_automated control (host hasn't reported that data yet)
        # shouldn't deflate the score just because a new control was added.
        "score_pct": round(met / len(scorable) * 100) if scorable else 0,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def list_frameworks() -> list[dict]:
    return [{"id": k, "name": v["name"], "control_count": len(v["controls"])} for k, v in FRAMEWORKS.items()]
