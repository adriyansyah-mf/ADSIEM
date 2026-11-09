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
"""
from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Any, Literal

IOC_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "email")
BLOCK_IP_DURATIONS = (3600, 86400, 604800)
MAX_BLOCK_AGENTS = 50
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
