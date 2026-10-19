# server-api/app/services/investigator.py
"""AI case investigation: an analyst clicks "Investigate" on a case and an LLM
agent works it like a DFIR analyst would — reads the case and its alerts,
searches the logs, runs live-response artifacts on the affected endpoints,
writes a new artifact when none fits, and ends with a report on the case.

Guardrails, enforced here rather than trusted to the prompt:

- Collection only. Live response goes through artifacts, whose plugins are all
  read-only collectors; the response actions (isolate, kill, quarantine, block)
  are tasks this agent has no tool for — the report recommends them and an
  operator runs them.
- Artifacts the AI writes are validated like any other (known plugins only,
  Sigma detection must compile), must be named AI.*, and can't shadow a
  built-in. read_file is refused on credential stores (shadow, SAM, private
  keys, ...), whatever artifact asks for it.
- Scoped to the case's group: hosts, artifacts and searches outside it are
  invisible, even when a superadmin starts the run.
- Budgets: model rounds, flows, new artifacts and wall-clock time; the last
  round forces a report instead of another tool call.
- Every step (tool call, flow, artifact) is recorded on the investigation and
  every flow names the investigation and the analyst who started it.
- Commands (run_command) exist only when Settings → ai_command_execution is
  "approval". Each one waits for a person with agents:manage to approve it,
  unless its program is on the admin's auto-approve list (never a shell or an
  interpreter, never touching a credential store). No shell on the agent side:
  the approved argv is what runs.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from fastapi import HTTPException
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from sqlalchemy import desc, select, text, update

from app.core.database import AsyncSessionLocal
from app.core.redis_client import get_redis
from app.models.models import (
    Agent, Alert, Case, CaseInvestigation, CaseNote, Flow, FlowArtifact, FlowLog, FlowRowBatch,
    HygieneSnapshot, InvestigationCommand, PlatformSetting, UebaAnomaly, User,
)
from app.services.audit import audit_log
from app.services.flow_artifacts import (
    PLUGINS, ArtifactError, builtin_artifacts, compile_request, parse_artifact, resolve_params,
)

log = structlog.get_logger()

MAX_ROUNDS = 18
MAX_FLOWS = 12
MAX_NEW_ARTIFACTS = 4
MAX_SECONDS = 30 * 60
FLOW_WAIT_CAP = 600          # longest a single flow is waited for
TOOL_RESULT_CHARS = 8_000    # what one tool result may put in the model's context
CONTEXT_CHARS = 60_000       # older tool results are shortened to keep the prompt under this
KEEP_FULL_RESULTS = 3        # ...except the most recent ones
STALE_AFTER = timedelta(minutes=5)  # a running investigation not updated this long is dead
MAX_COMMANDS = 8
APPROVAL_WAIT = 15 * 60      # a command nobody decides on in this long expires
COMMAND_MAX_TIMEOUT = 300    # the agent's exec cap
COMMAND_OUTPUT_CHARS = 6_000  # per stream, in the tool result

# Never auto-approved, whatever the allowlist says: these run arbitrary code.
INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "busybox", "env", "sudo", "su", "doas", "xargs", "find",
    "python", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk", "tclsh",
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "wmic", "msiexec",
}

# Investigation-relevant subset of the assistant's read-only tools.
READ_ONLY_TOOLS = {
    "get_alert", "search_alerts", "get_case", "correlate_entity", "reconstruct_timeline", "pivot_ioc",
    "search_events", "aggregate_events", "event_timeline", "recent_fim_changes", "agent_hygiene",
    "ueba_top_risky_entities", "search_sop",
}

# read_file never returns these, whichever artifact asks: credentials don't go to an LLM.
SENSITIVE_PATH = re.compile(
    r"(?i)(^|[/\\])(shadow|gshadow|master\.passwd|sudoers)$"
    r"|[/\\]\.ssh[/\\]id_[^/\\]*$|\.(pem|key|p12|pfx|kdbx|keytab)$"
    r"|[/\\]config[/\\](sam|security|system)$|ntds\.dit$|[/\\]\.aws[/\\]credentials$"
    r"|\.git-credentials$|[/\\]login data$|[/\\]\.docker[/\\]config\.json$"
)

PLUGIN_REFERENCE = """Plugins (all read-only; the agent's OS decides which work):
- info: host facts. Columns Hostname, OS, OSRelease, Kernel, Arch, UptimeSec.
- pslist: processes. Pid, Ppid, Name, Username, Exe, CommandLine, StartTime(win), RssKb, Threads.
- netstat: sockets. Proto, LocalAddr, LocalPort, RemoteAddr, RemotePort, State, Pid, Process.
- users: local accounts. Linux: Username, Uid, Gid, Home, Shell. Windows: Username, Uid(SID), Enabled, Admin, LastLogon.
- persistence: autostarts (Linux cron/systemd/profiles/authorized_keys/sudoers; Windows Run keys, Startup, tasks, services, WMI). Category, Path, Content, ModTime.
- glob: args globs (list, '*' one level, '**' any depth, '{a,b}' alternatives), max_results. Path, Name, Size, Mode, Uid, ModTime, IsDir.
- hash: args globs, max_results. Path, Size, MD5, SHA1, SHA256.
- read_file: args path, max_bytes. Path, Size, Truncated, SHA256, Encoding, Data. (Credential stores are refused.)
- yara: args path, recursive. Scans with the platform's enabled YARA rules. Rule, File, Size, Strings.
- dmesg (Linux), open_files (Linux): kernel ring buffer; open file descriptors.
- eventlog (Windows): args channel (e.g. Security, System, Microsoft-Windows-Sysmon/Operational), event_ids ("4624,4625"), hours (0 = all), limit. Columns TimeCreated, EventID, Channel, Provider, Computer plus the event's EventData fields (e.g. TargetUserName, IpAddress, LogonType, Image, CommandLine).
- services (Windows): Name, DisplayName, State, StartMode, Account, Pid, PathName.
- programs (Windows): Name, Version, Publisher, InstallDate, InstallLocation, Scope."""

ARTIFACT_EXAMPLE = """name: AI.Windows.ProcessesFromTemp
description: Processes whose image lives in a Temp folder.
parameters:
  - name: PathPart
    default: '\\Temp\\'
sources:
  - name: Procs
    plugin: pslist
    detection:            # optional Sigma filter applied to the rows (server side)
      selection:
        Exe|contains: '{{PathPart}}'
      condition: selection
    fields: [Pid, Ppid, Name, Username, Exe, CommandLine]"""

SYSTEM_PROMPT = f"""You are a senior DFIR analyst investigating a security case on a SIEM platform. You work autonomously: nobody answers questions mid-investigation, so decide, act, and conclude.

Method:
1. Read the case context you are given (alerts, hosts, IOCs, prior notes). Form hypotheses about what happened.
2. Gather evidence. Search the SIEM's logs and alerts (search_events, event_timeline, correlate_entity, pivot_ioc, reconstruct_timeline, ...) and collect live data from the affected endpoints with run_artifact: running processes, network connections, persistence, accounts, event logs, suspicious files. Prefer targeted artifacts and parameters over dumping everything.
3. When no existing artifact (list_artifacts) collects what you need, write one with create_artifact, then run it. Artifacts are YAML; names must start with "AI." (e.g. AI.Linux.CronFromTmp). Only the plugins below exist.
4. Pivot on what you find (a suspicious PID → its parent and connections; an IP → other hosts; a file → its hash and how it persists). Use get_flow_rows to search a large result instead of re-running the artifact.
5. Stop when the evidence answers the question or the budget runs low, and write the report.

You can only collect. You cannot isolate hosts, kill processes, delete or quarantine files, block IPs or change anything — put those in the report as recommended actions for the operator.

Budget: about {MAX_ROUNDS} reasoning rounds, {MAX_FLOWS} live-response runs, {MAX_NEW_ARTIFACTS} new artifacts. Flows on offline agents never return; check a host's status first.

{PLUGIN_REFERENCE}

Artifact YAML example:
{ARTIFACT_EXAMPLE}

Final report (your last message, no tool calls), in the analyst's language if the case is written in Indonesian, otherwise English, as Markdown with these sections:
## Summary — what happened, in 2–4 sentences.
## Evidence — each finding with where it came from (flow id + artifact, or the log search).
## Indicators — IPs, domains, hashes, files, accounts, processes worth tracking.
## Timeline — key events in order, with timestamps.
## Recommended actions — concrete containment and remediation steps for the operator, most urgent first.
## Gaps — what you could not check and why.
End with one line exactly: VERDICT: true_positive | false_positive | inconclusive"""

NO_COMMANDS_PROMPT = "\n\nYou cannot run commands or scripts on hosts; collect with artifacts only."

COMMANDS_PROMPT = f"""

Commands: run_command asks to run one program on a host when no artifact can collect what you need. There is no shell — give the program and its arguments as a list (Linux: ss -tnp, lsof -p 4242, journalctl -u ssh --since -2h, last -F, auditctl -l, crontab -l -u www-data; Windows: netstat -ano, schtasks /query /fo csv /v, ipconfig /displaydns, or powershell -NoProfile -Command "<one pipeline>" for PowerShell).
- An analyst sees every command with your reason and approves or rejects it before it runs; it then runs as root / SYSTEM. Give a short, specific reason.
- Read-only diagnostics only: never modify, delete, kill, stop, install, download, upload or send anything, and never read credential stores. Containment stays a recommendation in the report.
- A rejected or expired command must not be asked for again; adapt and use what you have.
- Budget: {MAX_COMMANDS} commands; each waits for approval (up to {APPROVAL_WAIT // 60} minutes) and runs for at most {COMMAND_MAX_TIMEOUT} s."""


class Cancelled(Exception):
    pass


@dataclass
class Ctx:
    inv_id: uuid.UUID
    case_id: uuid.UUID
    group_id: str
    user_id: uuid.UUID | None
    username: str
    started: float = field(default_factory=time.monotonic)
    flows: int = 0
    artifacts: int = 0
    flow_ids: set[str] = field(default_factory=set)
    commands_enabled: bool = False
    autoapprove: frozenset[str] = frozenset()
    commands: int = 0

    def seconds_left(self) -> float:
        return MAX_SECONDS - (time.monotonic() - self.started)


# ─── Persistence of progress ─────────────────────────────────────

async def _step(inv_id: uuid.UUID, kind: str, **data) -> None:
    """Append one step (atomically: the UI polls while this runs)."""
    step = {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind, **data}
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE case_investigations SET steps = steps || CAST(:s AS jsonb), updated_at = now() "
                 "WHERE id = :id"),
            {"s": json.dumps([step], default=str), "id": inv_id},
        )
        await db.commit()


async def _set(inv_id: uuid.UUID, **values) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(update(CaseInvestigation).where(CaseInvestigation.id == inv_id).values(**values))
        await db.commit()


async def _check_cancel(ctx: Ctx) -> None:
    async with AsyncSessionLocal() as db:
        inv = await db.get(CaseInvestigation, ctx.inv_id)
        if inv is None or inv.cancel_requested:
            raise Cancelled()
    if ctx.seconds_left() <= 0:
        raise Cancelled("time budget exhausted")


def _clip(value: Any, n: int = 300) -> Any:
    if isinstance(value, str) and len(value) > n:
        return value[:n] + f"…(+{len(value) - n} chars)"
    return value


def _json(obj: Any, limit: int = TOOL_RESULT_CHARS) -> str:
    s = json.dumps(obj, default=str, ensure_ascii=False)
    return s if len(s) <= limit else s[:limit] + '…(truncated — narrow the query or use offsets)"'


# ─── Case context ────────────────────────────────────────────────

async def _host_info(db, agent: Agent) -> dict:
    snap = (await db.execute(
        select(HygieneSnapshot.os_name, HygieneSnapshot.os_version)
        .where(HygieneSnapshot.agent_id == agent.id).order_by(desc(HygieneSnapshot.collected_at)).limit(1)
    )).first()
    return {
        "agent_id": str(agent.id), "hostname": agent.hostname, "status": agent.status,
        "last_seen": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "os": " ".join(x for x in (snap or ()) if x) or None,
        "live_response": agent.flow_poll_at is not None and agent.approved is not False,
        "isolated": agent.is_isolated,
    }


async def case_context(ctx: Ctx) -> dict:
    async with AsyncSessionLocal() as db:
        case = await db.get(Case, ctx.case_id)
        alerts = []
        host_names: set[str] = set()
        agent_ids: set[uuid.UUID] = set()
        if case.alert_id:
            a = await db.get(Alert, case.alert_id)
            if a:
                alerts.append({
                    "id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status,
                    "hostname": a.hostname, "source_ip": a.source_ip, "created_at": a.created_at,
                    "mitre": a.mitre_techniques, "context": a.context, "ai_verdict": a.ai_verdict,
                })
                if a.hostname:
                    host_names.add(a.hostname)
                if a.agent_id:
                    agent_ids.add(a.agent_id)
        anomalies = [
            {"entity": f"{u.entity_type}:{u.entity_value}", "score": u.risk_score, "reasons": u.reasons,
             "detected_at": u.detected_at}
            for u in (await db.execute(
                select(UebaAnomaly).where(UebaAnomaly.case_id == case.id).limit(10))).scalars()
        ]
        for ioc in (case.ioc_data or {}).get("hostnames", []) or []:
            host_names.add(str(ioc))
        q = select(Agent).where(Agent.group_id == ctx.group_id)
        agents = [ag for ag in (await db.execute(q)).scalars()
                  if ag.id in agent_ids or ag.hostname in host_names]
        notes = [
            {"at": n.created_at, "ai": n.is_ai_generated, "text": _clip(n.content, 600)}
            for n in (await db.execute(
                select(CaseNote).where(CaseNote.case_id == case.id).order_by(desc(CaseNote.created_at)).limit(8)
            )).scalars()
        ]
        return {
            "case": {"id": str(case.id), "title": case.title, "description": case.description,
                     "severity": case.severity, "status": case.status, "created_at": case.created_at,
                     "iocs": case.ioc_data, "ai_reasoning": _clip(case.ai_reasoning or "", 800)},
            "alerts": alerts,
            "ueba_anomalies": anomalies,
            "hosts": [await _host_info(db, ag) for ag in agents],
            "recent_notes": notes,
        }


# ─── Tools ───────────────────────────────────────────────────────

async def _resolve_agent(db, ctx: Ctx, host: str) -> Agent:
    q = select(Agent).where(Agent.group_id == ctx.group_id)
    try:
        q = q.where(Agent.id == uuid.UUID(host))
    except ValueError:
        q = q.where(Agent.hostname.ilike(host.strip()))
    agent = (await db.execute(q.limit(1))).scalar_one_or_none()
    if agent is None:
        raise ValueError(f"no agent '{host}' in this case's group (use list_hosts)")
    return agent


async def list_hosts(ctx: Ctx, hostname_contains: str = "") -> dict:
    async with AsyncSessionLocal() as db:
        q = select(Agent).where(Agent.group_id == ctx.group_id).order_by(Agent.hostname).limit(50)
        if hostname_contains:
            q = q.where(Agent.hostname.ilike(f"%{hostname_contains}%"))
        return {"hosts": [await _host_info(db, ag) for ag in (await db.execute(q)).scalars()]}


async def _all_artifacts(ctx: Ctx) -> dict:
    arts = dict(builtin_artifacts())
    async with AsyncSessionLocal() as db:
        for row in (await db.execute(select(FlowArtifact).where(FlowArtifact.group_id == ctx.group_id))).scalars():
            try:
                arts.setdefault(row.name, parse_artifact(row.content))
            except ArtifactError:
                continue
    return arts


async def list_artifacts(ctx: Ctx, os: str = "any") -> dict:
    os = (os or "any").lower()
    out = []
    for name, art in sorted((await _all_artifacts(ctx)).items()):
        lname = name.lower()
        if os == "windows" and "linux." in lname or os == "linux" and "windows." in lname:
            continue
        out.append({
            "name": name,
            "description": (art.description or "").strip().split("\n")[0][:160],
            "params": {p.name: p.default for p in art.parameters},
            "plugins": sorted({s.plugin for s in art.sources}),
        })
    return {"artifacts": out}


async def _flow_summary(flow_id: uuid.UUID, rows_per_source: int = 20) -> dict:
    async with AsyncSessionLocal() as db:
        flow = await db.get(Flow, flow_id)
        sources = [s["name"] for s in (flow.request or {}).get("sources", [])]
        out_sources = []
        for name in sources:
            batches = (await db.execute(
                select(FlowRowBatch.rows).where(FlowRowBatch.flow_id == flow_id, FlowRowBatch.source == name)
                .order_by(FlowRowBatch.id)
            )).scalars().all()
            rows = [r for b in batches for r in b]
            out_sources.append({
                "source": name,
                "total_rows": len(rows),
                "columns": sorted({k for r in rows[:200] for k in r}),
                "rows": [{k: _clip(v) for k, v in r.items()} for r in rows[:rows_per_source]],
            })
        errors = [m for (m,) in (await db.execute(
            select(FlowLog.message).where(FlowLog.flow_id == flow_id, FlowLog.level == "error").limit(5)
        )).all()]
        return {"flow_id": str(flow_id), "artifact": flow.artifact, "status": flow.status, "error": flow.error,
                "errors": errors, "sources": out_sources,
                "note": "Showing the first rows of each source; get_flow_rows pages or searches the rest."}


async def _wait_flow(ctx: Ctx, flow_id: uuid.UUID, flow_timeout: int) -> str:
    """Poll a flow until it ends or the wait cap runs out; returns its last status."""
    from app.api.routes.flows import TERMINAL

    deadline = time.monotonic() + min(flow_timeout + 60, FLOW_WAIT_CAP, max(ctx.seconds_left(), 30))
    status = "scheduled"
    while time.monotonic() < deadline:
        await asyncio.sleep(3)
        async with AsyncSessionLocal() as db:
            status = (await db.execute(select(Flow.status).where(Flow.id == flow_id))).scalar_one()
        if status in TERMINAL:
            break
        await _check_cancel(ctx)
        await _set(ctx.inv_id, updated_at=datetime.now(timezone.utc))  # alive, for mark_stale_interrupted
    return status


async def run_artifact(ctx: Ctx, artifact: str, host: str, params: dict | None = None, reason: str = "") -> dict:
    from app.api.routes.flows import TERMINAL, _load_artifact, schedule_flow

    if ctx.flows >= MAX_FLOWS:
        return {"error": f"live-response budget used up ({MAX_FLOWS} runs); write the report"}
    params = params or {}
    redis = await get_redis()
    async with AsyncSessionLocal() as db:
        agent = await _resolve_agent(db, ctx, host)
        if agent.status != "online":
            return {"error": f"{agent.hostname} is {agent.status} (last seen {agent.last_seen_at}); "
                             "a flow would never be picked up"}
        art = await _load_artifact(db, artifact, ctx.group_id)
        try:
            probe = compile_request(art, "probe", resolve_params(art, params), 60, 1)
        except ArtifactError as exc:
            return {"error": f"bad parameters: {exc}"}
        for src in probe["sources"]:
            path = str((src.get("args") or {}).get("path", ""))
            if src["plugin"] == "read_file" and SENSITIVE_PATH.search(path):
                await _step(ctx.inv_id, "refused", reason=f"read_file on a credential store: {path}")
                return {"error": f"refused: {path} holds credentials and is never read by the AI"}
        flow = await schedule_flow(
            db, redis, agent_id=agent.id, artifact=artifact, params=params, group_filter=ctx.group_id,
            created_by=ctx.user_id, scheduled_by=f"AI investigation {ctx.inv_id} (started by {ctx.username})",
        )
        flow_id, hostname, flow_timeout = flow.id, agent.hostname, flow.timeout
    ctx.flows += 1
    ctx.flow_ids.add(str(flow_id))
    await _step(ctx.inv_id, "flow", flow_id=str(flow_id), artifact=artifact, host=hostname,
                params=params, reason=reason)

    status = await _wait_flow(ctx, flow_id, flow_timeout)
    summary = await _flow_summary(flow_id)
    if status not in TERMINAL:
        summary["note"] = (f"still {status} after waiting; partial rows shown — the agent may be slow or "
                           "offline. get_flow_rows can read more later.")
    await _step(ctx.inv_id, "flow_result", flow_id=str(flow_id), status=summary["status"],
                rows={s["source"]: s["total_rows"] for s in summary["sources"]})
    return summary


async def get_flow_rows(ctx: Ctx, flow_id: str, source: str = "", contains: str = "",
                        offset: int = 0, limit: int = 50) -> dict:
    if flow_id not in ctx.flow_ids:
        return {"error": "only flows this investigation ran can be read"}
    limit = max(1, min(int(limit or 50), 100))
    async with AsyncSessionLocal() as db:
        flow = await db.get(Flow, uuid.UUID(flow_id))
        names = [s["name"] for s in (flow.request or {}).get("sources", [])]
        source = source or (names[0] if names else "")
        batches = (await db.execute(
            select(FlowRowBatch.rows).where(FlowRowBatch.flow_id == flow.id, FlowRowBatch.source == source)
            .order_by(FlowRowBatch.id)
        )).scalars().all()
    rows = [r for b in batches for r in b]
    if contains:
        needle = contains.lower()
        rows = [r for r in rows if any(needle in str(v).lower() for v in r.values())]
    page = rows[int(offset or 0): int(offset or 0) + limit]
    return {"flow_id": flow_id, "source": source, "matching_rows": len(rows), "offset": offset,
            "rows": [{k: _clip(v, 500) for k, v in r.items()} for r in page]}


async def create_artifact(ctx: Ctx, yaml_text: str, reason: str = "") -> dict:
    if ctx.artifacts >= MAX_NEW_ARTIFACTS:
        return {"error": f"new-artifact budget used up ({MAX_NEW_ARTIFACTS})"}
    try:
        art = parse_artifact(yaml_text)
    except ArtifactError as exc:
        return {"error": f"invalid artifact: {exc}"}
    if not art.name.startswith("AI."):
        return {"error": "artifact names must start with 'AI.' (e.g. AI.Linux.CronFromTmp)"}
    if art.name in builtin_artifacts():
        return {"error": f"{art.name} is built in; pick another name"}
    unknown = {s.plugin for s in art.sources} - PLUGINS
    if unknown:
        return {"error": f"unknown plugins {sorted(unknown)}"}
    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(FlowArtifact).where(FlowArtifact.name == art.name))).scalar_one_or_none()
        if existing is not None:
            if existing.group_id == ctx.group_id and existing.content.strip() == yaml_text.strip():
                return {"created": art.name, "note": "identical artifact already existed; run it"}
            return {"error": f"an artifact named {art.name} already exists; choose another name"}
        db.add(FlowArtifact(name=art.name, description=f"[AI investigation] {art.description or ''}".strip(),
                            content=yaml_text, group_id=ctx.group_id, created_by=ctx.user_id))
        await db.commit()
    ctx.artifacts += 1
    await _step(ctx.inv_id, "artifact", name=art.name, reason=reason, yaml=yaml_text)
    await audit_log(None, ctx.user_id, "ai_artifact_created", "flow_artifact", art.name,
                    {"investigation": str(ctx.inv_id)})
    return {"created": art.name, "sources": [s.name for s in art.sources],
            "params": {p.name: p.default for p in art.parameters}}


def _program(command: str) -> str:
    """Bare, lower-case program name: /usr/bin/Whoami.EXE → whoami."""
    name = re.split(r"[/\\]", command.strip())[-1].lower()
    return re.sub(r"\.(exe|com|bat|cmd|ps1)$", "", name)


def command_line(command: str, args: list[str]) -> str:
    return " ".join([command] + [a if a and not re.search(r"\s|\"", a) else json.dumps(a) for a in args])


def auto_approvable(command: str, args: list[str], allowlist: frozenset[str]) -> bool:
    """Runs without a human only when the admin listed the program, it can't run
    arbitrary code, and no argument points at a credential store."""
    prog = _program(command)
    if not prog or prog not in allowlist or prog in INTERPRETERS:
        return False
    return not any(SENSITIVE_PATH.search(a) for a in [command, *args])


async def _await_decision(ctx: Ctx, cmd_id: uuid.UUID) -> InvestigationCommand:
    """Wait for an analyst to approve or reject; expire it after APPROVAL_WAIT.
    Time spent waiting doesn't count against the investigation's clock."""
    started = time.monotonic()
    deadline = started + APPROVAL_WAIT
    try:
        while True:
            async with AsyncSessionLocal() as db:
                cmd = await db.get(InvestigationCommand, cmd_id)
                if cmd.status != "pending":
                    return cmd
                if time.monotonic() >= deadline:
                    await db.execute(update(InvestigationCommand).where(
                        InvestigationCommand.id == cmd_id, InvestigationCommand.status == "pending",
                    ).values(status="expired", decided_at=datetime.now(timezone.utc)))
                    await db.commit()
                    continue  # re-read: an approval may have landed just now
            await _check_cancel(ctx)
            await _set(ctx.inv_id, updated_at=datetime.now(timezone.utc))
            await asyncio.sleep(2)
    finally:
        ctx.started += time.monotonic() - started


async def run_command(ctx: Ctx, host: str, command: str, args: list | None = None, reason: str = "",
                      timeout: int = 60) -> dict:
    if not ctx.commands_enabled:
        return {"error": "running commands is disabled on this platform; use artifacts"}
    if ctx.commands >= MAX_COMMANDS:
        return {"error": f"command budget used up ({MAX_COMMANDS}); write the report"}
    command = (command or "").strip()
    if not command:
        return {"error": "command is required (the program, e.g. 'ss' or 'netstat')"}
    if isinstance(args, str):
        return {"error": "args must be a list of strings, one per argument (there is no shell)"}
    args = [str(a) for a in (args or [])]
    if len(command) + sum(len(a) for a in args) > 4000:
        return {"error": "command too long"}
    timeout = max(1, min(int(timeout or 60), COMMAND_MAX_TIMEOUT))
    if not reason.strip():
        return {"error": "give a reason: the analyst approving the command sees it"}

    async with AsyncSessionLocal() as db:
        agent = await _resolve_agent(db, ctx, host)
        if agent.status != "online":
            return {"error": f"{agent.hostname} is {agent.status}; the command would never run"}
        auto = auto_approvable(command, args, ctx.autoapprove)
        cmd = InvestigationCommand(
            investigation_id=ctx.inv_id, group_id=ctx.group_id, agent_id=agent.id, hostname=agent.hostname,
            command=command, args=args, timeout=timeout, reason=reason.strip()[:2000],
            status="approved" if auto else "pending", auto_approved=auto,
            decided_at=datetime.now(timezone.utc) if auto else None,
        )
        db.add(cmd)
        await db.commit()
        cmd_id, agent_id, hostname = cmd.id, agent.id, agent.hostname
    ctx.commands += 1
    line = command_line(command, args)
    await _step(ctx.inv_id, "command", command_id=str(cmd_id), host=hostname, command=line,
                reason=reason, auto_approved=auto)

    if not auto:
        cmd = await _await_decision(ctx, cmd_id)
        if cmd.status != "approved":
            await _step(ctx.inv_id, "command_decision", command_id=str(cmd_id), status=cmd.status,
                        note=cmd.decision_note)
            why = f" ({cmd.decision_note})" if cmd.decision_note else ""
            return {"error": f"the analyst did not run this command: {cmd.status}{why}. "
                             "Don't ask for it again; adapt or write the report."}
        await _step(ctx.inv_id, "command_decision", command_id=str(cmd_id), status="approved")

    from app.api.routes.flows import schedule_command_flow
    redis = await get_redis()
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        decided_by = (await db.get(InvestigationCommand, cmd_id)).decided_by
        flow = await schedule_command_flow(
            db, redis, agent=agent, command=command, args=args, timeout=timeout,
            created_by=decided_by or ctx.user_id,
            scheduled_by=f"AI investigation {ctx.inv_id} (started by {ctx.username}), command "
                         f"{'auto-approved' if auto else 'approved by an analyst'}",
        )
        await db.execute(update(InvestigationCommand).where(InvestigationCommand.id == cmd_id)
                         .values(flow_id=flow.id))
        await db.commit()
        flow_id, flow_timeout = flow.id, flow.timeout
    ctx.flow_ids.add(str(flow_id))
    await audit_log(None, decided_by or ctx.user_id, "ai_command_run", "agent", str(agent_id),
                    {"investigation": str(ctx.inv_id), "command": line, "auto_approved": auto})

    status = await _wait_flow(ctx, flow_id, flow_timeout)
    async with AsyncSessionLocal() as db:
        batches = (await db.execute(select(FlowRowBatch.rows).where(FlowRowBatch.flow_id == flow_id)
                                    .order_by(FlowRowBatch.id))).scalars().all()
        flow = await db.get(Flow, flow_id)
    rows = [r for b in batches for r in b]
    streams = {s: "\n".join(str(r.get("Text", "")) for r in rows if r.get("Stream") == s)
               for s in ("stdout", "stderr")}
    exit_row = next((r for r in rows if r.get("Stream") == "exit"), None)
    result = {
        "host": hostname, "command": line, "flow_id": str(flow_id), "status": status,
        "exit": exit_row.get("Text") if exit_row else None,
        "error": flow.error,
        "stdout": _clip(streams["stdout"], COMMAND_OUTPUT_CHARS),
        "stderr": _clip(streams["stderr"], COMMAND_OUTPUT_CHARS // 3),
    }
    if len(streams["stdout"]) > COMMAND_OUTPUT_CHARS:
        result["note"] = "stdout was shortened; get_flow_rows with contains= searches all of it"
    await _step(ctx.inv_id, "command_result", command_id=str(cmd_id), flow_id=str(flow_id), status=status,
                exit=result["exit"], error=flow.error, lines=sum(1 for r in rows if r.get("Stream") != "exit"))
    return result


async def _expire_pending(inv_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(update(InvestigationCommand).where(
            InvestigationCommand.investigation_id == inv_id, InvestigationCommand.status == "pending",
        ).values(status="expired", decided_at=datetime.now(timezone.utc)))
        await db.commit()


async def command_settings(db) -> tuple[bool, frozenset[str]]:
    mode = await db.get(PlatformSetting, "ai_command_execution")
    allow = await db.get(PlatformSetting, "ai_command_autoapprove")
    enabled = bool(mode and (mode.value or "").strip().lower() == "approval")
    names = frozenset(_program(n) for n in ((allow.value if allow else "") or "").split(",") if n.strip())
    return enabled, names


def build_tools(ctx: Ctx) -> list[StructuredTool]:
    from app.services.assistant_tools import TOOLS as ASSISTANT_TOOLS, run_tool

    def tool(fn, name, description, schema):
        async def _run(**kwargs):
            await _check_cancel(ctx)
            try:
                return await fn(ctx, **kwargs)
            except Cancelled:
                raise
            except HTTPException as exc:
                return {"error": exc.detail}
            except Exception as exc:  # noqa: BLE001 — the model gets the error and can adapt
                log.warning("investigator_tool_failed", tool=name, error=str(exc))
                return {"error": str(exc)}
        return StructuredTool.from_function(coroutine=_run, name=name, description=description, args_schema=schema)

    tools = [
        tool(list_hosts, "list_hosts", "Agents in this case's group with status, OS and whether live response works.",
             {"type": "object", "properties": {"hostname_contains": {"type": "string"}}}),
        tool(list_artifacts, "list_artifacts", "Live-response artifacts you can run, with parameters and plugins.",
             {"type": "object", "properties": {"os": {"type": "string", "enum": ["any", "windows", "linux"]}}}),
        tool(run_artifact, "run_artifact",
             "Run a live-response artifact on one host and wait for its rows (first rows of each source are returned).",
             {"type": "object", "required": ["artifact", "host"], "properties": {
                 "artifact": {"type": "string"}, "host": {"type": "string", "description": "hostname or agent id"},
                 "params": {"type": "object", "description": "artifact parameters by name"},
                 "reason": {"type": "string", "description": "why — shown to the analyst"}}}),
        tool(get_flow_rows, "get_flow_rows",
             "Page through or search (substring, any column) the rows of a flow this investigation ran.",
             {"type": "object", "required": ["flow_id"], "properties": {
                 "flow_id": {"type": "string"}, "source": {"type": "string"}, "contains": {"type": "string"},
                 "offset": {"type": "integer"}, "limit": {"type": "integer"}}}),
        tool(create_artifact, "create_artifact",
             "Save a new artifact (YAML, name starting with AI.) when no existing one collects what you need.",
             {"type": "object", "required": ["yaml_text"], "properties": {
                 "yaml_text": {"type": "string"}, "reason": {"type": "string"}}}),
    ]
    if ctx.commands_enabled:
        tools.append(tool(
            run_command, "run_command",
            "Ask to run one read-only program on a host (no shell). An analyst approves it first; "
            "returns its stdout, stderr and exit code.",
            {"type": "object", "required": ["host", "command", "args", "reason"], "properties": {
                "host": {"type": "string", "description": "hostname or agent id"},
                "command": {"type": "string", "description": "the program, e.g. ss, netstat, powershell"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "one entry per argument"},
                "reason": {"type": "string", "description": "why — the approving analyst reads this"},
                "timeout": {"type": "integer", "description": f"seconds, at most {COMMAND_MAX_TIMEOUT}"}}}))

    for spec in ASSISTANT_TOOLS:
        name = spec["name"]
        if name not in READ_ONLY_TOOLS:
            continue
        schema = spec.get("schema") or {
            "type": "object",
            "properties": {p: {"type": "string", "description": str(h)} for p, h in (spec.get("parameters") or {}).items()},
        }

        async def _ro(_name=name, **kwargs):
            await _check_cancel(ctx)
            async with AsyncSessionLocal() as db:
                return await run_tool(_name, kwargs, db, ctx.group_id)

        tools.append(StructuredTool.from_function(coroutine=_ro, name=name,
                                                  description=spec.get("description", ""), args_schema=schema))
    return tools


# ─── The loop ────────────────────────────────────────────────────

async def investigation_model(db, default: str) -> str:
    """Settings → investigation_model, else the assistant's model. Investigations
    need native tool calling and a long context — a stronger model than chat."""
    from app.models.models import PlatformSetting
    row = await db.get(PlatformSetting, "investigation_model")
    return (row.value or "").strip() if row and (row.value or "").strip() else default


def make_chat_model(api_key: str, model: str, effort: str | None):
    """The LLM client; tests replace this with a scripted model."""
    from app.core.config import settings
    from app.core.graph.chat_model import NineRouterChatModel
    # long prompts (case context + tool results) take a while: wider timeout than chat
    return NineRouterChatModel(base_url=settings.NINEROUTER_BASE_URL, api_key=api_key, model=model,
                               max_tokens=4000, reasoning_effort=effort, timeout=180.0)


_VERDICT_RE = re.compile(r"VERDICT:\s*(true_positive|false_positive|inconclusive)", re.I)


# ─── Model output hygiene ────────────────────────────────────────
# Models routed through a 9router combo vary: some answer with native tool
# calls, some write them as text (Qwen's <function=...> XML, Hermes' JSON in
# <tool_call>), and small ones degenerate into <unk> runs when the prompt gets
# long. All three are handled here rather than surfacing as garbage.

_TOOL_CALL_BLOCK = re.compile(r"<tool_call>\s*(.*?)\s*(?:</tool_call>|$)", re.S)
_XML_FUNCTION = re.compile(r"<function=([\w.-]+)>(.*?)(?:</function>|$)", re.S)
_XML_PARAM = re.compile(r"<parameter=([\w.-]+)>\s*(.*?)\s*</parameter>", re.S)


def _param_value(raw: str) -> Any:
    raw = raw.strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def parse_text_tool_calls(content: str, known: set[str]) -> tuple[list[dict], str]:
    """Tool calls written as text → (calls, the content without them). Only names of real tools count."""
    calls: list[dict] = []
    for m in _XML_FUNCTION.finditer(content):
        name = m.group(1)
        if name in known:
            calls.append({"name": name, "args": {k: _param_value(v) for k, v in _XML_PARAM.findall(m.group(2))}})
    if not calls:
        for m in _TOOL_CALL_BLOCK.finditer(content):
            try:
                obj = json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                continue
            name = obj.get("name") if isinstance(obj, dict) else None
            args = obj.get("arguments", obj.get("parameters", {})) if isinstance(obj, dict) else {}
            if isinstance(args, str):
                args = _param_value(args)
            if name in known and isinstance(args, dict):
                calls.append({"name": name, "args": args})
    if not calls:
        return [], content
    for i, c in enumerate(calls):
        c["id"] = f"text_call_{uuid.uuid4().hex[:8]}_{i}"
    cut = min((i for i in (content.find("<tool_call>"), content.find("<function=")) if i >= 0), default=len(content))
    return calls, content[:cut].strip()


def is_degenerate(text: str) -> bool:
    """<unk> runs or one short chunk repeated over and over: the model lost the thread."""
    if not text:
        return False
    if text.count("<unk>") >= 3:
        return True
    tail = text.rstrip()[-2000:]
    for n in range(1, 41):  # the end is one unit repeated back to back
        unit = tail[-n:]
        reps = max(12, 240 // n)
        if unit.strip() and len(tail) >= n * reps and tail.endswith(unit * reps):
            return True
    return False


def _compact(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Shorten older tool results once the conversation outgrows CONTEXT_CHARS."""
    total = sum(len(str(m.content)) for m in messages)
    if total <= CONTEXT_CHARS:
        return messages
    tool_idx = [i for i, m in enumerate(messages) if isinstance(m, ToolMessage)]
    out = list(messages)
    for i in tool_idx[:-KEEP_FULL_RESULTS]:
        body = str(out[i].content)
        if len(body) > 1200:
            out[i] = ToolMessage(content=body[:1200] + " …(older result shortened; re-read it with get_flow_rows "
                                 "or repeat the search if you need it)", tool_call_id=out[i].tool_call_id,
                                 name=out[i].name)
            total -= len(body) - len(str(out[i].content))
        if total <= CONTEXT_CHARS:
            break
    return out


async def _ask(ctx: Ctx, model, messages: list[BaseMessage], known: set[str]):
    """One model turn, with text tool calls recovered and one retry on degenerate output."""
    for attempt in range(2):
        reply = await model.ainvoke(_compact(messages))
        content = str(reply.content or "")
        calls = list(getattr(reply, "tool_calls", None) or [])
        if not calls:
            calls, content = parse_text_tool_calls(content, known)
        if not is_degenerate(content):
            return content, calls
        await _step(ctx.inv_id, "warning", text="the model produced corrupted output; retrying with a shorter context")
        messages = messages + [HumanMessage(content=(
            "Your previous reply was corrupted (repeated or unknown tokens) and was discarded. "
            "Continue concisely: call one tool, or write the final report."))]
    return "", []


async def _investigate(ctx: Ctx, api_key: str, model: str, effort: str | None) -> tuple[str, str]:
    tools = build_tools(ctx)
    by_name = {t.name: t for t in tools}
    chat = make_chat_model(api_key, model, effort)
    llm = chat.bind_tools(tools)

    context = await case_context(ctx)
    await _step(ctx.inv_id, "context", hosts=[h["hostname"] for h in context["hosts"]],
                alerts=[a["title"] for a in context["alerts"]])
    messages: list[BaseMessage] = [
        SystemMessage(content=SYSTEM_PROMPT + (COMMANDS_PROMPT if ctx.commands_enabled else NO_COMMANDS_PROMPT)),
        HumanMessage(content="Investigate this case. Context:\n" + _json(context, 20_000)),
    ]

    for round_no in range(1, MAX_ROUNDS + 1):
        await _check_cancel(ctx)
        final = round_no == MAX_ROUNDS or ctx.seconds_left() < 120
        if final:
            messages.append(HumanMessage(content="Budget exhausted: write the final report now, no more tools."))
        content, calls = await _ask(ctx, chat if final else llm, messages, set(by_name))
        if not content and not calls:
            if final:
                return "", "inconclusive"
            # degenerate twice: stop collecting and go straight to the report
            messages.append(HumanMessage(content="Stop investigating and write the final report now."))
            content, _ = await _ask(ctx, chat, messages, set())
            m = _VERDICT_RE.search(content)
            return content.strip(), (m.group(1).lower() if m else "inconclusive")
        messages.append(AIMessage(content=content, tool_calls=calls))
        if content and calls:
            await _step(ctx.inv_id, "thought", text=_clip(content, 1500))
        if not calls or final:
            report = content.strip()
            m = _VERDICT_RE.search(report)
            return report, (m.group(1).lower() if m else "inconclusive")

        for call in calls:
            name, args = call.get("name", ""), call.get("args") or {}
            await _step(ctx.inv_id, "tool", tool=name,
                        args={k: _clip(v, 400) if isinstance(v, str) else v for k, v in args.items()})
            tool = by_name.get(name)
            result = {"error": f"unknown tool {name}"} if tool is None else await tool.ainvoke(args)
            messages.append(ToolMessage(content=_json(result), tool_call_id=call.get("id") or name, name=name))
    return "", "inconclusive"  # unreachable: the last round always answers


async def run_investigation(inv_id: uuid.UUID) -> None:
    """Background task: run one investigation to completion and store the outcome."""
    from app.services.assistant import _graph_config

    async with AsyncSessionLocal() as db:
        inv = await db.get(CaseInvestigation, inv_id)
        user = await db.get(User, inv.started_by) if inv.started_by else None
        ctx = Ctx(inv_id=inv.id, case_id=inv.case_id, group_id=inv.group_id,
                  user_id=inv.started_by, username=user.username if user else "unknown")
        api_key, model, effort = await _graph_config(db, inv.group_id)
        model = await investigation_model(db, model)
        ctx.commands_enabled, ctx.autoapprove = await command_settings(db)
    await _set(inv_id, status="running", model=model)
    await _step(inv_id, "started", by=ctx.username, model=model, commands=ctx.commands_enabled)
    try:
        report, verdict = await _investigate(ctx, api_key, model, effort)
        if not report:
            raise RuntimeError("the model returned an empty report")
        async with AsyncSessionLocal() as db:
            db.add(CaseNote(case_id=ctx.case_id, author_id=None, is_ai_generated=True,
                            content=f"**AI investigation** ({verdict.replace('_', ' ')}; "
                                    f"{ctx.flows} live-response runs, {ctx.commands} commands, "
                                    f"started by {ctx.username})\n\n{report}"))
            await db.execute(update(CaseInvestigation).where(CaseInvestigation.id == inv_id).values(
                status="finished", report=report, verdict=verdict, finished_at=datetime.now(timezone.utc)))
            await db.commit()
        await _step(inv_id, "finished", verdict=verdict, flows=ctx.flows, artifacts=ctx.artifacts,
                    commands=ctx.commands)
    except Cancelled as exc:
        await _set(inv_id, status="cancelled", error=str(exc) or "cancelled by an analyst",
                   finished_at=datetime.now(timezone.utc))
        await _step(inv_id, "cancelled", reason=str(exc) or "cancelled by an analyst")
    except Exception as exc:  # noqa: BLE001
        log.exception("investigation_failed", investigation=str(inv_id))
        await _set(inv_id, status="error", error=str(exc)[:2000], finished_at=datetime.now(timezone.utc))
        await _step(inv_id, "error", error=str(exc)[:500])
    finally:
        await _expire_pending(inv_id)  # nothing may be approved after the run that asked for it ended


_running: set[asyncio.Task] = set()


def spawn(inv_id: uuid.UUID) -> None:
    task = asyncio.create_task(run_investigation(inv_id))
    _running.add(task)
    task.add_done_callback(_running.discard)


async def mark_stale_interrupted() -> None:
    """At startup: runs whose process died (no update for a while) can't finish."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(CaseInvestigation)
            .where(CaseInvestigation.status.in_(("queued", "running")),
                   CaseInvestigation.updated_at < datetime.now(timezone.utc) - STALE_AFTER)
            .values(status="interrupted", error="the server restarted during the investigation",
                    finished_at=datetime.now(timezone.utc))
        )
        await db.execute(
            update(InvestigationCommand)
            .where(InvestigationCommand.status == "pending",
                   InvestigationCommand.investigation_id.in_(
                       select(CaseInvestigation.id).where(CaseInvestigation.status == "interrupted")))
            .values(status="expired", decided_at=datetime.now(timezone.utc))
        )
        await db.commit()
