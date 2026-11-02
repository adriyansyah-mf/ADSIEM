# server-api/app/services/process_tree.py
"""The process tree around an alert's process, from the logs index.

No sensor gives a process a unique id, so a process is the most recent
process-creation event with its pid on the alert's agent before the time
it matters (a child's start, or the alert): pids are reused, the latest
start before the moment wins. Ancestors are followed up to MAX_DEPTH;
children and grandchildren are the starts whose parent pid is theirs,
after their start and before the pid started something else.

Each process also gets its file, network, DNS and known-malware events,
and its exit when the sensor reports one (Linux)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Awaitable, Callable

Search = Callable[..., Awaitable[tuple[list[dict], int, list | None]]]

# process starts; every one of these decoders has ProcessId / ParentProcessId
EXEC_LOG_TYPES = ("linux_process_exec", "windows_etw_process")
EXEC_DECODERS = ("win_sysmon_1_process_created",)
ACTIVITY_LOG_TYPES = ("linux_file_event", "windows_etw_file", "linux_network_connect", "linux_network_accept",
                      "windows_etw_network", "linux_dns_query", "windows_etw_dns", "known_malware",
                      "linux_process_exit")
MAX_DEPTH = 10
LOOKBACK = timedelta(days=3)
LOOKAHEAD = timedelta(hours=1)
CLOCK_SKEW = timedelta(seconds=60)
MAX_CHILDREN = 100
MAX_EVENTS = 500
EVENTS_PER_PROCESS = 50

_SHA256 = re.compile(r"SHA256=([0-9A-Fa-f]{64})")


def _ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _first(d: dict, *keys) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def anchor_of(fields: dict) -> dict:
    """pid, parent pid and image of the process an alert's event is about."""
    return {
        "pid": _first(fields, "process.pid", "ProcessId", "PID"),
        "ppid": _first(fields, "process.parent.pid", "ParentProcessId", "PPID"),
        "image": _first(fields, "process.executable", "Image", "file.path"),
        "parent_image": _first(fields, "process.parent.executable", "ParentImage"),
        "command_line": _first(fields, "process.command_line", "CommandLine"),
        "user": _first(fields, "user.name", "User", "user.id"),
        "sha256": _first(fields, "file.hash.sha256", "process.hash.sha256").lower() or _sha_from(fields),
    }


def _sha_from(fields: dict) -> str:
    m = _SHA256.search(_first(fields, "Hashes", "process.hash"))
    return m.group(1).lower() if m else ""


def process_of(doc: dict) -> dict:
    """A process-creation document as a tree node."""
    f = doc.get("decoded_fields") or {}
    return {
        "id": doc["id"],
        "pid": _first(f, "ProcessId", "process.pid"),
        "ppid": _first(f, "ParentProcessId", "process.parent.pid"),
        "image": _first(f, "Image", "process.executable"),
        "command_line": _first(f, "CommandLine", "process.command_line"),
        "parent_image": _first(f, "ParentImage", "process.parent.executable"),
        "user": _first(f, "User", "user.name"),
        "integrity": _first(f, "IntegrityLevel"),
        "sha256": _sha_from(f),
        "start": doc.get("created_at"),
        "log_type": doc.get("log_type"),
    }


def _pid_query(field: str, pids: list[str]) -> dict:
    # match, not term: kv values are text+keyword, json ones may be numbers
    return {"bool": {"should": [{"match": {f"decoded_fields.{field}": p}} for p in pids], "minimum_should_match": 1}}


def _exec_filter() -> dict:
    return {"bool": {"should": [{"terms": {"log_type": list(EXEC_LOG_TYPES)}},
                                {"terms": {"decoder": list(EXEC_DECODERS)}}], "minimum_should_match": 1}}


def _range(start: datetime | None, end: datetime | None) -> dict:
    r: dict = {}
    if start:
        r["gte"] = start.isoformat()
    if end:
        r["lte"] = end.isoformat()
    return {"range": {"created_at": r}}


async def _latest_start(search: Search, agent_id: str, pid: str, before: datetime, after: datetime) -> dict | None:
    q = {"bool": {"filter": [{"term": {"agent_id": agent_id}}, _exec_filter(), _range(after, before),
                             _pid_query("ProcessId", [pid])]}}
    hits, _, _ = await search(q, size=1, sort=[{"created_at": "desc"}])
    return process_of(hits[0]) if hits else None


async def _children(search: Search, agent_id: str, parents: list[dict], until: datetime) -> list[dict]:
    if not parents:
        return []
    start = min(_ts(p["start"]) for p in parents if _ts(p["start"]))
    q = {"bool": {"filter": [{"term": {"agent_id": agent_id}}, _exec_filter(), _range(start, until),
                             _pid_query("ParentProcessId", sorted({p["pid"] for p in parents}))]}}
    hits, _, _ = await search(q, size=MAX_CHILDREN, sort=[{"created_at": "asc"}])
    out = []
    for h in hits:
        child = process_of(h)
        t = _ts(child["start"])
        # the parent is the latest start of that pid before the child
        cands = [p for p in parents if p["pid"] == child["ppid"] and _ts(p["start"]) and _ts(p["start"]) <= t]
        if cands:
            child["parent_id"] = max(cands, key=lambda p: _ts(p["start"]))["id"]
            out.append(child)
    return out


def _event_of(doc: dict) -> dict:
    f = doc.get("decoded_fields") or {}
    lt = doc.get("log_type") or ""
    kind = ("file" if "file" in lt else "dns" if "dns" in lt else "malware" if lt == "known_malware"
            else "exit" if lt == "linux_process_exit" else "network")
    detail = {
        "file": lambda: {"path": _first(f, "file.path", "TargetFilename"),
                         "action": _first(f, "file.action", "FileAction", "event.action")},
        "network": lambda: {"destination": _first(f, "destination.address", "destination.ip", "DestinationIp"),
                            "port": _first(f, "destination.port", "DestinationPort"),
                            "direction": _first(f, "network.direction") or ("inbound" if "accept" in lt else "outbound")},
        "dns": lambda: {"query": _first(f, "dns.question.name", "QueryName"), "answers": _first(f, "dns.answers")},
        "malware": lambda: {"label": _first(f, "malware.label"), "action": _first(f, "malware.action"),
                            "sha256": _first(f, "file.hash.sha256"), "path": _first(f, "file.path")},
        "exit": lambda: {"code": _first(f, "process.exit_code")},
    }[kind]()
    return {"id": doc["id"], "kind": kind, "time": doc.get("created_at"), "pid": _first(f, "process.pid", "ProcessId"),
            **detail}


async def _activity(search: Search, agent_id: str, nodes: list[dict], until: datetime) -> list[dict]:
    starts = [_ts(n["start"]) for n in nodes if _ts(n["start"])]
    if not starts:
        return []
    q = {"bool": {"filter": [{"term": {"agent_id": agent_id}}, {"terms": {"log_type": list(ACTIVITY_LOG_TYPES)}},
                             _range(min(starts), until),
                             _pid_query("process.pid", sorted({n["pid"] for n in nodes if n["pid"]}))]}}
    hits, _, _ = await search(q, size=MAX_EVENTS, sort=[{"created_at": "asc"}])
    return [_event_of(h) for h in hits]


def _assign(nodes: list[dict], events: list[dict]) -> None:
    """An event belongs to the latest start of its pid at or before it."""
    by_pid: dict[str, list[dict]] = {}
    for n in nodes:
        n.setdefault("events", [])
        n.setdefault("counts", {})
        by_pid.setdefault(n["pid"], []).append(n)
    for e in events:
        t = _ts(e["time"])
        owners = [n for n in by_pid.get(e["pid"], []) if _ts(n["start"]) and t and _ts(n["start"]) - CLOCK_SKEW <= t]
        if not owners:
            continue
        n = max(owners, key=lambda x: _ts(x["start"]))
        n["counts"][e["kind"]] = n["counts"].get(e["kind"], 0) + 1
        if e["kind"] == "exit":
            n["exited"] = e["time"]
            n["exit_code"] = e.get("code", "")
        elif len(n["events"]) < EVENTS_PER_PROCESS:
            n["events"].append(e)


async def for_alert(db, alert) -> dict:
    """build() for an alert: its event from the logs index, its agent, and
    the agent's details (the API route and the AI tool use this)."""
    from uuid import UUID
    from datetime import timezone

    from app.core.es_client import get_log, search
    from app.models.models import Agent

    doc = await get_log(str(alert.event_id)) if alert.event_id else None
    agent_id = str(alert.agent_id) if alert.agent_id else (doc or {}).get("agent_id")
    tree = await build(search, agent_id, doc, alert.created_at or datetime.now(timezone.utc))
    agent = await db.get(Agent, UUID(agent_id)) if agent_id else None
    tree["agent"] = ({"id": str(agent.id), "hostname": agent.hostname, "status": agent.status,
                      "is_isolated": agent.is_isolated, "version": agent.version} if agent else None)
    return tree


def compact(tree: dict, events_per_process: int = 8, max_nodes: int = 40) -> dict:
    """The tree for a language model: short command lines, a few events each."""
    nodes = []
    for n in tree.get("nodes", [])[:max_nodes]:
        nodes.append({k: v for k, v in {
            "id": n["id"], "pid": n["pid"], "image": n["image"], "command_line": (n.get("command_line") or "")[:300],
            "parent_id": n.get("parent_id"), "depth": n["depth"], "alert_process": bool(n.get("anchor")),
            "user": n.get("user"), "start": n.get("start"), "exited": n.get("exited"), "sha256": n.get("sha256"),
            "no_start_recorded": bool(n.get("synthetic")), "event_counts": n.get("counts") or {},
            "events": [{k: v for k, v in e.items() if k not in ("id", "pid") and v}
                       for e in (n.get("events") or [])[:events_per_process]],
        }.items() if v not in (None, "", [], {}, False) or k in ("depth", "pid", "image")})
    return {"hostname": (tree.get("agent") or {}).get("hostname"), "nodes": nodes,
            "notes": tree.get("notes", []) + ([f"{len(tree['nodes']) - max_nodes} more processes not shown"]
                                               if len(tree.get("nodes", [])) > max_nodes else [])}


async def build(search: Search, agent_id: str | None, event: dict | None, at: datetime) -> dict:
    """{anchor, nodes, notes}: nodes carry parent_id (None at the top) and depth (0 = anchor)."""
    notes: list[str] = []
    fields = (event or {}).get("decoded_fields") or {}
    a = anchor_of(fields)
    if not agent_id:
        return {"anchor": None, "nodes": [], "notes": ["The alert has no agent, so there is no process to show."]}
    if not a["pid"]:
        return {"anchor": None, "nodes": [], "notes": ["The alert's event names no process (no pid)."]}

    event_time = _ts((event or {}).get("created_at")) or at
    oldest = event_time - LOOKBACK
    anchor = await _latest_start(search, agent_id, a["pid"], event_time + CLOCK_SKEW, oldest)
    if anchor is None:
        # no start event (telemetry off, or it started before the lookback): the alert's own fields
        anchor = {"id": f"event:{(event or {}).get('id', '')}", "pid": a["pid"], "ppid": a["ppid"],
                  "image": a["image"], "command_line": a["command_line"], "parent_image": a["parent_image"],
                  "user": a["user"], "integrity": "", "sha256": "", "start": event_time.isoformat(),
                  "log_type": (event or {}).get("log_type"), "synthetic": True}
        notes.append("No process start was recorded for this pid in the last 3 days; the process is shown from "
                     "the alert's event.")
    if a["sha256"] and not anchor.get("sha256"):
        anchor["sha256"] = a["sha256"]
    anchor.update(parent_id=None, depth=0, anchor=True)
    nodes = [anchor]

    # ancestors
    child = anchor
    for depth in range(1, MAX_DEPTH + 1):
        if not child["ppid"] or child["ppid"] in ("0", child["pid"]):
            break
        parent = await _latest_start(search, agent_id, child["ppid"], _ts(child["start"]) + CLOCK_SKEW, oldest)
        if parent is None:
            nodes.append({"id": f"parent:{child['ppid']}", "pid": child["ppid"], "ppid": "", "image": child["parent_image"],
                          "command_line": "", "parent_image": "", "user": "", "integrity": "", "sha256": "",
                          "start": None, "log_type": None, "synthetic": True, "parent_id": None, "depth": -depth})
            child["parent_id"] = nodes[-1]["id"]
            break
        parent.update(parent_id=None, depth=-depth)
        child["parent_id"] = parent["id"]
        nodes.append(parent)
        child = parent

    # children and grandchildren
    until = event_time + LOOKAHEAD
    level, depth = [anchor], 0
    while level and depth < 2:
        depth += 1
        kids = await _children(search, agent_id, level, until)
        for k in kids:
            k["depth"] = depth
        nodes.extend(kids)
        level = kids
    if len([n for n in nodes if n["depth"] > 0]) >= MAX_CHILDREN:
        notes.append(f"More than {MAX_CHILDREN} child processes; the first ones are shown.")

    events = await _activity(search, agent_id, [n for n in nodes if n.get("start")], until)
    _assign(nodes, events)
    if len(events) >= MAX_EVENTS:
        notes.append(f"Only the first {MAX_EVENTS} file and network events are shown.")
    nodes.sort(key=lambda n: (n["depth"], str(n.get("start") or "")))
    return {"anchor": anchor["id"], "nodes": nodes, "notes": notes}
