# server-api/app/services/investigation_chat_actions.py
"""What the investigation chat may propose (services/investigation_chat.py).

A proposal never runs when the model asks for it: the tool call is checked here
and stored as an investigation_chat_actions row with status `proposed`; an
analyst with the tool's permission approves it later. `permission` names who
may approve: "case" (cases:manage — evidence and IoCs) or "endpoint"
(agents:manage — anything that reaches an agent or the web block list).

validate_proposal() is the one gate between model output and a row. It checks
the arguments' shape here; existence and scope of the targets (agent in the
case's group and online, artifact enabled, public IP, normalised domain) are
checked again when the action is decided, by the executors next to it.

decide() is the only way a proposal runs: the approver's permission for the
tool's class is checked, the row moves proposed → approved|rejected in one
conditional UPDATE (so a double click or a second analyst gets 409 and nothing
runs twice), then an approved action executes at once through the same code
paths as the dashboard, and the outcome is stored, posted to the chat as a
system message and audited.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Literal

import structlog
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import es_client
from app.models.models import (
    Agent, AgentTask, Alert, Case, CaseInvestigation, Flow, FlowArtifact, InvestigationChatAction,
    InvestigationEvidence, InvestigationMessage,
)
from app.services import web_blocks
from app.services.audit import audit_log
from worker.web_domains import DomainError, normalize as normalize_domain

log = structlog.get_logger()

IOC_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "email")
BLOCK_IP_DURATIONS = (3600, 86400, 604800)
MAX_BLOCK_AGENTS = 20
MAX_VALUE = 2048
MAX_REASON = 2000


class ProposalError(ValueError):
    """The model's arguments can't become a proposal; the message goes back to the model."""


@dataclass(frozen=True)
class ChatCtx:
    inv_id: uuid.UUID
    case_id: uuid.UUID
    group_id: str
    user_id: uuid.UUID | None


@dataclass(frozen=True)
class ProposalTool:
    description: str
    schema: dict[str, Any]
    permission: Literal["case", "endpoint"]


_REASON = {"type": "string", "description": "why — the approving analyst reads this"}
_AGENT = {"type": "string", "description": "agent id (UUID) from the case context or a tool result"}
_IOC_TYPE = {"type": "string", "enum": list(IOC_TYPES)}


def _obj(required: list[str], **props) -> dict[str, Any]:
    return {"type": "object", "required": required, "properties": props}


PROPOSAL_TOOLS: dict[str, ProposalTool] = {
    "pin_evidence": ProposalTool(
        "Propose pinning an evidence item of this investigation so it stays on top.",
        _obj(["evidence_id"], evidence_id={"type": "string"}, reason=_REASON), "case"),
    "add_case_ioc": ProposalTool(
        "Propose adding an indicator to the case's IoCs.",
        _obj(["type", "value", "reason"], type=_IOC_TYPE, value={"type": "string"}, reason=_REASON), "case"),
    "remove_case_ioc": ProposalTool(
        "Propose removing an indicator from the case's IoCs (e.g. a benign one such as public DNS).",
        _obj(["type", "value", "reason"], type=_IOC_TYPE, value={"type": "string"}, reason=_REASON), "case"),
    "add_threat_ioc": ProposalTool(
        "Propose adding an indicator to the Threat IoCs list, tied to this case.",
        _obj(["type", "value", "reason"], type=_IOC_TYPE, value={"type": "string"}, reason=_REASON), "case"),
    "isolate_host": ProposalTool(
        "Propose network-isolating a host (only the SIEM connection stays up).",
        _obj(["agent_id", "reason"], agent_id=_AGENT, reason=_REASON), "endpoint"),
    "unisolate_host": ProposalTool(
        "Propose lifting a host's network isolation.",
        _obj(["agent_id", "reason"], agent_id=_AGENT, reason=_REASON), "endpoint"),
    "block_domain": ProposalTool(
        "Propose blocking a domain on every agent of the case's group (web protection).",
        _obj(["domain", "reason"], domain={"type": "string"}, reason=_REASON,
             days={"type": "integer", "description": "expire after this many days; omit for no expiry"}),
        "endpoint"),
    "block_ip": ProposalTool(
        "Propose blocking an IP on some hosts' firewalls for a while.",
        _obj(["agent_ids", "ip", "duration_seconds", "reason"],
             agent_ids={"type": "array", "items": {"type": "string"}, "description": "agent ids (UUIDs)"},
             ip={"type": "string"},
             duration_seconds={"type": "integer", "enum": list(BLOCK_IP_DURATIONS)}, reason=_REASON),
        "endpoint"),
    "kill_process": ProposalTool(
        "Propose killing a process on a host.",
        _obj(["agent_id", "pid", "reason"], agent_id=_AGENT, pid={"type": "integer"}, reason=_REASON), "endpoint"),
    "quarantine_file": ProposalTool(
        "Propose quarantining a file on a host (absolute path).",
        _obj(["agent_id", "path", "reason"], agent_id=_AGENT, path={"type": "string"}, reason=_REASON), "endpoint"),
    "run_live_response": ProposalTool(
        "Propose running a registered live-response artifact on a host (read-only collection).",
        _obj(["agent_id", "artifact", "reason"], agent_id=_AGENT, artifact={"type": "string"},
             params={"type": "object", "description": "artifact parameters by name"}, reason=_REASON),
        "endpoint"),
}


def _text(args: dict, key: str, *, required: bool = True, limit: int = MAX_VALUE) -> str | None:
    value = args.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ProposalError(f"{key} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise ProposalError(f"{key} is longer than {limit} characters")
    return value


def _int(args: dict, key: str, *, required: bool = True) -> int | None:
    value = args.get(key)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProposalError(f"{key} must be an integer")
    return value


def _agent_id(value: Any, key: str = "agent_id") -> str:
    if not isinstance(value, str):
        raise ProposalError(f"{key} must be an agent id (UUID)")
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError:
        raise ProposalError(f"{key} must be an agent id (UUID), not {value[:80]!r}") from None


def _ioc(args: dict) -> tuple[str, dict]:
    kind = _text(args, "type")
    if kind not in IOC_TYPES:
        raise ProposalError(f"type must be one of {', '.join(IOC_TYPES)}")
    value = _text(args, "value")
    return f"{kind}:{value}", {"type": kind, "value": value}


def validate_proposal(tool: str, args: dict, ctx: ChatCtx) -> tuple[str, dict]:
    """(target, params) for a proposal row, or ProposalError. `reason` is not in params."""
    if tool not in PROPOSAL_TOOLS:
        raise ProposalError(f"unknown proposal tool {tool!r}")
    if not isinstance(args, dict):
        raise ProposalError("arguments must be an object")
    if tool != "pin_evidence":
        _text(args, "reason", limit=MAX_REASON)

    if tool == "pin_evidence":
        try:
            evidence = str(uuid.UUID(str(args.get("evidence_id") or "")))
        except ValueError:
            raise ProposalError("evidence_id must be an evidence id from list_evidence") from None
        return evidence, {"evidence_id": evidence}
    if tool in ("add_case_ioc", "remove_case_ioc", "add_threat_ioc"):
        return _ioc(args)
    if tool in ("isolate_host", "unisolate_host"):
        agent = _agent_id(args.get("agent_id"))
        return agent, {"agent_id": agent}
    if tool == "block_domain":
        domain = _text(args, "domain", limit=253)
        days = _int(args, "days", required=False)
        if days is not None and not 1 <= days <= 365:
            raise ProposalError("days must be between 1 and 365")
        return domain, {"domain": domain, "days": days}
    if tool == "block_ip":
        ip = _text(args, "ip", limit=64)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ProposalError(f"{ip!r} is not an IP address") from None
        agents = args.get("agent_ids")
        if not isinstance(agents, list) or not 1 <= len(agents) <= MAX_BLOCK_AGENTS:
            raise ProposalError(f"agent_ids must list 1 to {MAX_BLOCK_AGENTS} agent ids")
        agents = sorted({_agent_id(a, "agent_ids") for a in agents})
        duration = _int(args, "duration_seconds")
        if duration not in BLOCK_IP_DURATIONS:
            raise ProposalError(f"duration_seconds must be one of {BLOCK_IP_DURATIONS}")
        return ip, {"ip": ip, "agent_ids": agents, "duration_seconds": duration}
    if tool == "kill_process":
        agent = _agent_id(args.get("agent_id"))
        pid = _int(args, "pid")
        if pid <= 0:
            raise ProposalError("pid must be positive")
        return agent, {"agent_id": agent, "pid": pid}
    if tool == "quarantine_file":
        agent = _agent_id(args.get("agent_id"))
        path = _text(args, "path", limit=4096)
        if not (path.startswith("/") or (len(path) > 2 and path[1] == ":" and path[2] in "\\/")):
            raise ProposalError("path must be absolute")
        return agent, {"agent_id": agent, "path": path}
    # run_live_response
    agent = _agent_id(args.get("agent_id"))
    artifact = _text(args, "artifact", limit=200)
    params = args.get("params") or {}
    if not isinstance(params, dict):
        raise ProposalError("params must be an object of artifact parameters")
    return agent, {"agent_id": agent, "artifact": artifact, "params": params}


# ─── deciding and executing ────────────────────────────────────────────

EXPIRY = timedelta(hours=24)
PERMISSIONS = {"case": "cases:manage", "endpoint": "agents:manage"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}  # worker/alert_iocs.py
THREAT_IOC_TITLE = "Added from investigation chat"
_HASH_LEN = {"sha256": 64, "sha1": 40, "md5": 32}
_HEX = re.compile(r"^[0-9a-f]+$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://[^/\s]+")


class DecisionError(Exception):
    """The decision itself is refused (404/403/409); nothing changed."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class ActionFailed(Exception):
    """An approved action could not run; the message is stored on the row."""


def may_decide(user, tool: str) -> bool:
    """Superadmin, or the permission of the tool's class (as require_permission checks it)."""
    if user.role.name == "superadmin":
        return True
    return PERMISSIONS[PROPOSAL_TOOLS[tool].permission] in {p.name for p in user.role.permissions}


def normalize_ioc(kind: str, value: str) -> str:
    """The canonical form the worker writes (worker/alert_iocs.py), or ActionFailed."""
    raw = str(value or "").strip()
    bad = ActionFailed(f"{raw[:200]!r} is not a valid {kind}")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            raise bad from None
    if kind == "domain":
        try:
            return normalize_domain(raw)
        except DomainError:
            raise bad from None
    if kind == "url":
        if not _URL.match(raw):
            raise bad
        return raw.lower()
    if kind in _HASH_LEN:
        low = raw.lower()
        if len(low) != _HASH_LEN[kind] or not _HEX.match(low):
            raise bad
        return low
    if kind == "email":
        low = raw.lower()
        if not _EMAIL.match(low):
            raise bad
        return low
    raise ActionFailed(f"unknown IoC type {kind!r}")


def threat_ioc_id(case_id, kind: str, value: str) -> str:
    return hashlib.sha1(f"case:{case_id}|{kind}|{value}".encode()).hexdigest()


@dataclass
class _Run:
    """One approved action being executed (plain values: the session may be rolled back)."""
    db: AsyncSession
    redis: Any
    user: Any
    approver: uuid.UUID | None
    action_id: uuid.UUID
    inv_id: uuid.UUID
    tool: str
    target: str | None
    params: dict
    reason: str
    case_id: uuid.UUID
    group: str
    severity: str
    alert_id: uuid.UUID | None


async def _agent(run: _Run, agent_id: str, *, online: bool) -> Agent:
    try:
        key = uuid.UUID(str(agent_id))
    except ValueError:
        raise ActionFailed(f"{agent_id!r} is not an agent id") from None
    agent = (await run.db.execute(select(Agent).where(Agent.id == key, Agent.group_id == run.group))).scalar_one_or_none()
    if agent is None:
        raise ActionFailed(f"agent {key} is not in this case's group")
    if online and agent.status != "online":
        raise ActionFailed(f"{agent.hostname} is not online ({agent.status})")
    return agent


async def _task(run: _Run, agent: Agent, task_type: str, params: dict) -> AgentTask:
    task = AgentTask(agent_id=agent.id, task_type=task_type, params=params, created_by=run.approver)
    run.db.add(task)
    return task


async def _locked_case(run: _Run) -> Case:
    return (await run.db.execute(select(Case).where(Case.id == run.case_id).with_for_update()
                                 .execution_options(populate_existing=True))).scalar_one()


async def _pin_evidence(run: _Run) -> dict:
    try:
        ev_id = uuid.UUID(str(run.params.get("evidence_id")))
    except ValueError:
        raise ActionFailed("evidence not found in this investigation") from None
    ev = (await run.db.execute(select(InvestigationEvidence).where(
        InvestigationEvidence.id == ev_id, InvestigationEvidence.investigation_id == run.inv_id))).scalar_one_or_none()
    if ev is None:
        raise ActionFailed("evidence not found in this investigation")
    ev.pinned = True
    title = ev.title
    await run.db.commit()
    return {"evidence_id": str(ev_id), "summary": f"pinned {title!r}"}


def _ioc_key(run: _Run) -> tuple[str, str, str]:
    kind = str(run.params.get("type") or "")
    if kind not in IOC_TYPES:
        raise ActionFailed(f"unknown IoC type {kind!r}")
    value = normalize_ioc(kind, run.params.get("value"))
    return kind, value, f"{kind}:{value}"


async def _add_case_ioc(run: _Run) -> dict:
    kind, value, key = _ioc_key(run)
    case = await _locked_case(run)
    ioc = dict(case.ioc_data or {})
    keys = list(ioc.get("ioc_keys") or [])
    added = key not in keys
    if added:
        ioc["ioc_keys"] = sorted({*keys, key})
        case.ioc_data = ioc
        case.updated_at = datetime.now(timezone.utc)
    await run.db.commit()
    return {"ioc_key": key, "added": added,
            "summary": f"added {key} to the case IoCs" if added else f"{key} was already a case IoC"}


async def _remove_case_ioc(run: _Run) -> dict:
    kind, value, key = _ioc_key(run)
    case = await _locked_case(run)
    ioc = dict(case.ioc_data or {})
    keys = list(ioc.get("ioc_keys") or [])
    removed = key in keys
    if removed:
        ioc["ioc_keys"] = [k for k in keys if k != key]
        case.ioc_data = ioc
        case.updated_at = datetime.now(timezone.utc)
    await run.db.commit()
    out: dict = {"ioc_key": key, "removed": removed}
    # the case's own Threat IoC doc goes too; alert-derived docs stay (they point at their alerts)
    try:
        out["threat_ioc_deleted"] = await es_client.delete_ioc(threat_ioc_id(run.case_id, kind, value))
    except Exception as exc:  # the case change stands; say what is left behind
        out["threat_ioc_deleted"] = False
        out["threat_ioc_error"] = f"{type(exc).__name__}: {exc}"[:300]
    if not removed and not out["threat_ioc_deleted"] and "threat_ioc_error" not in out:
        raise ActionFailed(f"{key} is not a case IoC")
    parts = [f"removed {key} from the case IoCs" if removed else f"{key} was not a case IoC"]
    if out["threat_ioc_deleted"]:
        parts.append("deleted its Threat IoC entry")
    if "threat_ioc_error" in out:
        parts.append(f"could not delete its Threat IoC entry ({out['threat_ioc_error']})")
    out["summary"] = "; ".join(parts)
    return out


async def _add_threat_ioc(run: _Run) -> dict:
    kind, value, key = _ioc_key(run)
    hostname = agent_id = None
    if run.alert_id is not None:
        alert = await run.db.get(Alert, run.alert_id)
        if alert is not None:
            hostname, agent_id = alert.hostname, str(alert.agent_id) if alert.agent_id else None
    severity = (run.severity or "medium").lower()
    doc_id = threat_ioc_id(run.case_id, kind, value)
    doc = {"alert_id": f"case:{run.case_id}", "group_id": run.group, "type": kind, "value": value, "ioc_key": key,
           "severity": severity, "severity_rank": SEVERITY_RANK.get(severity, 2), "hostname": hostname,
           "agent_id": agent_id, "rule_title": THREAT_IOC_TITLE, "ai_verdict": None, "origin": "analyst",
           "created_at": datetime.now(timezone.utc).isoformat()}
    try:
        await es_client.index_ioc(doc_id, doc)
    except Exception as exc:
        raise ActionFailed(f"could not write the Threat IoC: {type(exc).__name__}: {exc}"[:500]) from None
    return {"doc_id": doc_id, "ioc_key": key, "summary": f"added {key} to Threat IoCs"}


async def _isolate(run: _Run) -> dict:
    agent = await _agent(run, run.params.get("agent_id"), online=True)
    agent.is_isolated = True
    task = await _task(run, agent, "isolate_host", {})
    hostname = agent.hostname
    await run.db.commit()
    return {"task_id": str(task.id), "hostname": hostname, "summary": f"isolation queued for {hostname}"}


async def _unisolate(run: _Run) -> dict:
    agent = await _agent(run, run.params.get("agent_id"), online=False)
    agent.is_isolated = False
    task = await _task(run, agent, "unisolate_host", {})
    hostname = agent.hostname
    await run.db.commit()
    return {"task_id": str(task.id), "hostname": hostname, "summary": f"isolation lift queued for {hostname}"}


async def _block_domain(run: _Run) -> dict:
    days = run.params.get("days")
    if days is not None and (isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365):
        raise ActionFailed("days must be between 1 and 365")
    expires = datetime.now(timezone.utc) + timedelta(days=days) if days else None
    reason = f"AI chat: {run.reason}".strip()[:500]
    row = await web_blocks.block_domain(run.db, run.user, run.group, str(run.params.get("domain") or ""),
                                        reason, expires)
    await _audit(run.user, "web_block.add", "web_block", str(row.id), {"domain": row.domain, "group_id": run.group})
    return {"entry_id": str(row.id), "domain": row.domain,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "summary": f"{row.domain} blocked" + (f" for {days} days" if days else "")}


async def _block_ip(run: _Run) -> dict:
    try:
        ip = ipaddress.ip_address(str(run.params.get("ip") or ""))
    except ValueError:
        raise ActionFailed(f"{run.params.get('ip')!r} is not an IP address") from None
    if not ip.is_global:
        raise ActionFailed(f"{ip} is not a public IP; only public IPs are blocked")
    duration = run.params.get("duration_seconds")
    if duration not in BLOCK_IP_DURATIONS or isinstance(duration, bool):
        raise ActionFailed(f"duration_seconds must be one of {BLOCK_IP_DURATIONS}")
    try:
        ids = sorted({uuid.UUID(str(a)) for a in run.params.get("agent_ids") or []})
    except ValueError:
        raise ActionFailed("agent_ids must be agent ids") from None
    if not 1 <= len(ids) <= MAX_BLOCK_AGENTS:
        raise ActionFailed(f"block 1 to {MAX_BLOCK_AGENTS} hosts at a time")
    agents = (await run.db.execute(select(Agent).where(Agent.id.in_(ids), Agent.group_id == run.group)
                                   .order_by(Agent.hostname))).scalars().all()
    missing = sorted(set(ids) - {a.id for a in agents})
    if missing:
        raise ActionFailed(f"agent {', '.join(map(str, missing))} is not in this case's group")
    params = {"ip": str(ip), "duration_seconds": duration, "case_id": str(run.case_id)}
    tasks = [await _task(run, a, "block_ip", dict(params)) for a in agents]
    hosts = [a.hostname for a in agents]
    await run.db.commit()
    return {"task_ids": [str(t.id) for t in tasks], "hosts": hosts,
            "summary": f"block of {ip} for {duration}s queued on {', '.join(hosts)}"}


async def _kill_process(run: _Run) -> dict:
    pid = run.params.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ActionFailed("pid must be a positive integer")
    agent = await _agent(run, run.params.get("agent_id"), online=True)
    task = await _task(run, agent, "kill_process", {"pid": pid})
    hostname = agent.hostname
    await run.db.commit()
    return {"task_id": str(task.id), "hostname": hostname, "summary": f"kill of pid {pid} queued on {hostname}"}


def _absolute(path: str) -> bool:
    return path.startswith("/") or (len(path) > 2 and path[1] == ":" and path[2] in "\\/")


async def _quarantine(run: _Run) -> dict:
    path = str(run.params.get("path") or "").strip()
    if not _absolute(path):
        raise ActionFailed("path must be absolute")
    agent = await _agent(run, run.params.get("agent_id"), online=True)
    task = await _task(run, agent, "quarantine_file", {"path": path})
    hostname = agent.hostname
    await run.db.commit()
    return {"task_id": str(task.id), "hostname": hostname, "summary": f"quarantine of {path} queued on {hostname}"}


async def _live_response(run: _Run) -> dict:
    from app.api.routes.flows import _load_artifact, schedule_flow
    from app.services.flow_artifacts import ArtifactError, builtin_artifacts, compile_request, resolve_params
    from app.services.investigator import SENSITIVE_PATH

    agent = await _agent(run, run.params.get("agent_id"), online=True)
    name = str(run.params.get("artifact") or "")
    params = run.params.get("params") or {}
    if not isinstance(params, dict):
        raise ActionFailed("params must be an object")
    if name not in builtin_artifacts():
        row = (await run.db.execute(select(FlowArtifact).where(
            FlowArtifact.name == name, FlowArtifact.group_id == run.group))).scalar_one_or_none()
        if row is None:
            raise ActionFailed(f"artifact {name!r} not found")
        if name.startswith("AI.") and row.promoted_at is None and row.created_by_investigation_id != run.inv_id:
            raise ActionFailed(f"artifact {name!r} was written by another AI investigation and is not promoted")
    art = await _load_artifact(run.db, name, run.group)
    try:
        probe = compile_request(art, "probe", resolve_params(art, params), 60, 1)
    except ArtifactError as exc:
        raise ActionFailed(f"bad parameters: {exc}") from None
    for src in probe["sources"]:
        path = str((src.get("args") or {}).get("path", ""))
        if src["plugin"] in ("read_file", "filefeatures") and SENSITIVE_PATH.search(path):
            raise ActionFailed(f"refused: {path} holds credentials and is never collected from the chat")
    hostname = agent.hostname
    flow = await schedule_flow(
        run.db, run.redis, agent_id=agent.id, artifact=name, params=params, group_filter=run.group,
        created_by=run.approver,
        scheduled_by=f"investigation chat {run.inv_id} (approved by {run.user.username})")
    return {"flow_id": str(flow.id), "artifact": name, "hostname": hostname,
            "summary": f"{name} scheduled on {hostname}"}


EXECUTORS: dict[str, Callable[[_Run], Awaitable[dict]]] = {
    "pin_evidence": _pin_evidence,
    "add_case_ioc": _add_case_ioc,
    "remove_case_ioc": _remove_case_ioc,
    "add_threat_ioc": _add_threat_ioc,
    "isolate_host": _isolate,
    "unisolate_host": _unisolate,
    "block_domain": _block_domain,
    "block_ip": _block_ip,
    "kill_process": _kill_process,
    "quarantine_file": _quarantine,
    "run_live_response": _live_response,
}


async def expire_stale(db: AsyncSession, inv_id: uuid.UUID | None = None, action_id: uuid.UUID | None = None) -> None:
    """Proposals older than EXPIRY become `expired` (commits)."""
    q = update(InvestigationChatAction).where(
        InvestigationChatAction.status == "proposed",
        InvestigationChatAction.created_at < datetime.now(timezone.utc) - EXPIRY).values(status="expired")
    if inv_id is not None:
        q = q.where(InvestigationChatAction.investigation_id == inv_id)
    if action_id is not None:
        q = q.where(InvestigationChatAction.id == action_id)
    await db.execute(q.execution_options(synchronize_session=False))
    await db.commit()


async def flow_states(db: AsyncSession, actions) -> dict[uuid.UUID, dict]:
    """Live state of the flows that executed run_live_response actions scheduled, by action id."""
    by_flow: dict[uuid.UUID, uuid.UUID] = {}
    for a in actions:
        if a.tool == "run_live_response" and a.status == "executed" and (a.result or {}).get("flow_id"):
            try:
                by_flow[uuid.UUID(a.result["flow_id"])] = a.id
            except ValueError:
                continue
    if not by_flow:
        return {}
    rows = (await db.execute(select(Flow.id, Flow.status, Flow.total_rows, Flow.error)
                             .where(Flow.id.in_(list(by_flow))))).all()
    return {by_flow[fid]: {"flow_status": status, "flow_rows": rows_, "flow_error": error}
            for fid, status, rows_, error in rows}


async def _audit(user, action: str, resource_type: str, resource_id: str, detail: dict) -> None:
    """audit_log, but a failing audit store never strands an action half-way (it is logged instead)."""
    try:
        await audit_log(None, user.id, action, resource_type, resource_id, detail)
    except Exception:
        log.exception("chat_action_audit_failed", audit_action=action, resource_id=resource_id)


def _detail(action: InvestigationChatAction, user, note: str | None, **extra) -> dict:
    return {"investigation_id": str(action.investigation_id), "tool": action.tool, "target": action.target,
            "params": action.params, "reason": action.reason,
            "requester": str(action.requested_by) if action.requested_by else None,
            "approver": str(user.id), "note": note, **extra}


async def decide(db: AsyncSession, redis, action_id: uuid.UUID, user, group_filter: str | None,
                 approve: bool, note: str | None) -> tuple[InvestigationChatAction, InvestigationMessage]:
    """Approve (and run) or reject one proposal. Raises DecisionError."""
    q = select(InvestigationChatAction).where(InvestigationChatAction.id == action_id)
    if group_filter is not None:
        q = q.where(InvestigationChatAction.group_id == group_filter)
    action = (await db.execute(q)).scalar_one_or_none()
    if action is None:
        raise DecisionError(404, "Action not found")
    if action.tool not in PROPOSAL_TOOLS:
        raise DecisionError(409, f"Unknown action {action.tool!r}")
    if not may_decide(user, action.tool):
        raise DecisionError(403, f"Insufficient permissions: {PERMISSIONS[PROPOSAL_TOOLS[action.tool].permission]} "
                                 f"is needed to decide {action.tool}")

    now = datetime.now(timezone.utc)
    approver = await web_blocks.actor_id(db, user)
    claimed = (await db.execute(
        update(InvestigationChatAction)
        .where(InvestigationChatAction.id == action.id, InvestigationChatAction.status == "proposed",
               InvestigationChatAction.created_at >= now - EXPIRY)
        .values(status="approved" if approve else "rejected", decided_by=approver, decided_at=now)
        .returning(InvestigationChatAction.id)
        .execution_options(synchronize_session=False))).first()
    if claimed is None:
        await db.rollback()  # expires `action`: use the id we were given
        await expire_stale(db, action_id=action_id)
        status = (await db.execute(select(InvestigationChatAction.status)
                                   .where(InvestigationChatAction.id == action_id))).scalar_one()
        raise DecisionError(409, f"This action is already {status}")
    await db.commit()
    await db.refresh(action)

    note = (note or "").strip() or None
    who, what = user.username, f"{action.tool} on {action.target}"
    if not approve:
        content = f"{who} rejected {what}" + (f": {note}" if note else ".")
        message = InvestigationMessage(investigation_id=action.investigation_id, group_id=action.group_id,
                                       role="system", content=content, author_id=approver)
        db.add(message)
        await db.commit()
        await _audit(user, "ai_chat_action_rejected", "investigation_chat_action", str(action.id),
                     _detail(action, user, note))
        await db.refresh(action)
        return action, message

    await _audit(user, "ai_chat_action_approved", "investigation_chat_action", str(action.id),
                 _detail(action, user, note))
    inv = await db.get(CaseInvestigation, action.investigation_id)
    case = await db.get(Case, inv.case_id)
    run = _Run(db=db, redis=redis, user=user, approver=approver, action_id=action.id, inv_id=inv.id,
               tool=action.tool, target=action.target, params=dict(action.params or {}),
               reason=action.reason or "", case_id=case.id, group=case.group_id, severity=case.severity or "",
               alert_id=case.alert_id)
    group_id = action.group_id  # plain value: a failed executor rolls the session back
    result, error = None, None
    try:
        result = await EXECUTORS[action.tool](run)
    except ActionFailed as exc:
        error = str(exc)
    except HTTPException as exc:
        error = str(exc.detail)
    except Exception as exc:  # recorded on the row; the approval stands, so it never re-runs
        log.exception("chat_action_failed", action_id=str(action.id), tool=action.tool)
        error = f"{type(exc).__name__}: {exc}"[:500]
    if error is not None:
        await db.rollback()

    status = "executed" if error is None else "failed"
    await db.execute(update(InvestigationChatAction).where(InvestigationChatAction.id == run.action_id)
                     .values(status=status, result=result, error=error, executed_at=datetime.now(timezone.utc))
                     .execution_options(synchronize_session=False))
    if error is None:
        content = f"{who} approved {what}: done — {result.get('summary', 'ok')}."
    else:
        content = f"{who} approved {what}, but it failed: {error}"
    if note:
        content += f" (note: {note})"
    message = InvestigationMessage(investigation_id=run.inv_id, group_id=group_id, role="system",
                                   content=content, author_id=approver)
    db.add(message)
    await db.commit()
    await db.refresh(action)
    extra = {"result": result} if error is None else {"error": error}
    await _audit(user, f"ai_chat_action_{status}", "investigation_chat_action", str(action.id),
                 _detail(action, user, note, **extra))
    return action, message
