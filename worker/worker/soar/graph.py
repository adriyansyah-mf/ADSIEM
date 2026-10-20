"""Workflow graph: node catalog, validation, and conversion of old linear playbooks.

Graph shape (stored in soar_playbooks.graph):

    {"nodes": [{"id": "n1", "type": "trigger", "label": "...", "position": [x, y],
                "params": {...}, "retry": 0, "continue_on_error": false}],
     "edges": [{"from": "n1", "output": "main", "to": "n2"}]}

Nodes are keyed by a stable id (never by label), the graph must be a DAG with
exactly one trigger, and every node runs at most once per run.
"""
from __future__ import annotations

import re
from typing import Any

from worker.soar.template import TemplateError, parse_path, references

EVENTS = ("alert.created", "alert.triaged", "manual")
OPERATORS = ("eq", "neq", "gte", "lte", "gt", "lt", "in", "contains", "not_null", "is_null", "regex")
RESPONSE_OPS = ("isolate_host", "unisolate_host", "block_ip", "unblock_ip", "kill_process", "quarantine_file")
CASE_OPS = ("create_case", "add_note", "set_alert_status", "suppress")
ALERT_STATUSES = ("new", "acknowledged", "investigating", "resolved", "false_positive", "closed")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
BODY_TYPES = ("none", "json", "form", "text")
NOTIFY_CHANNELS = ("webhook", "discord", "slack")

MAX_NODES = 50
MAX_RETRY = 3
MAX_HTTP_TIMEOUT = 30
MAX_APPROVAL_MINUTES = 7 * 24 * 60

NODE_TYPES: dict[str, dict[str, Any]] = {
    "trigger":   {"outputs": ["main"], "label": "Trigger"},
    "if":        {"outputs": ["true", "false"], "label": "If"},
    "enrich":    {"outputs": ["main", "error"], "label": "Enrich (TI)"},
    "ai_decide": {"outputs": ["yes", "no", "error"], "label": "AI Decide"},
    "approval":  {"outputs": ["approved", "rejected"], "label": "Approval"},
    "response":  {"outputs": ["main", "error"], "label": "Response"},
    "case":      {"outputs": ["main", "error"], "label": "Case & Alert"},
    "notify":    {"outputs": ["main", "error"], "label": "Notify"},
    "http":      {"outputs": ["main", "error"], "label": "HTTP Request (curl)"},
}

_ID = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


class GraphError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _conditions_errors(where: str, cond_block: dict) -> list[str]:
    errs = []
    if cond_block.get("match", "all") not in ("all", "any"):
        errs.append(f"{where}: match must be 'all' or 'any'")
    conds = cond_block.get("conditions", [])
    if not isinstance(conds, list):
        return errs + [f"{where}: conditions must be a list"]
    for i, c in enumerate(conds):
        if not isinstance(c, dict):
            errs.append(f"{where}: condition {i + 1} is not an object")
            continue
        try:
            parse_path(str(c.get("field", "")))
        except TemplateError as exc:
            errs.append(f"{where}: condition {i + 1}: {exc}")
        if c.get("operator", "eq") not in OPERATORS:
            errs.append(f"{where}: condition {i + 1}: unknown operator {c.get('operator')!r}")
        if c.get("operator") == "regex" and len(str(c.get("value", ""))) > 200:
            errs.append(f"{where}: condition {i + 1}: regex longer than 200 characters")
    return errs


def _params_errors(node: dict) -> list[str]:
    t, p, where = node["type"], node.get("params") or {}, f"node {node['id']}"
    if not isinstance(p, dict):
        return [f"{where}: params must be an object"]
    errs: list[str] = []
    if t == "trigger":
        if p.get("event", "alert.created") not in EVENTS:
            errs.append(f"{where}: event must be one of {', '.join(EVENTS)}")
        errs += _conditions_errors(where, p)
    elif t == "if":
        errs += _conditions_errors(where, p)
    elif t == "ai_decide":
        if not str(p.get("question", "")).strip():
            errs.append(f"{where}: question is required")
        try:
            if not 0 <= float(p.get("min_confidence", 0.6)) <= 1:
                raise ValueError
        except (TypeError, ValueError):
            errs.append(f"{where}: min_confidence must be between 0 and 1")
    elif t == "approval":
        try:
            if not 1 <= int(p.get("timeout_minutes", 60)) <= MAX_APPROVAL_MINUTES:
                raise ValueError
        except (TypeError, ValueError):
            errs.append(f"{where}: timeout_minutes must be between 1 and {MAX_APPROVAL_MINUTES}")
    elif t == "response":
        op = p.get("operation")
        if op not in RESPONSE_OPS:
            errs.append(f"{where}: operation must be one of {', '.join(RESPONSE_OPS)}")
        if op == "kill_process" and not p.get("pid"):
            errs.append(f"{where}: pid is required for kill_process")
        if op == "quarantine_file" and not p.get("path"):
            errs.append(f"{where}: path is required for quarantine_file")
    elif t == "case":
        op = p.get("operation")
        if op not in CASE_OPS:
            errs.append(f"{where}: operation must be one of {', '.join(CASE_OPS)}")
        if op == "set_alert_status" and p.get("status") not in ALERT_STATUSES:
            errs.append(f"{where}: status must be one of {', '.join(ALERT_STATUSES)}")
        if op == "suppress" and p.get("entity_type", "ip") not in ("ip", "hostname", "rule_title"):
            errs.append(f"{where}: entity_type must be ip, hostname or rule_title")
    elif t == "notify":
        if p.get("channel", "webhook") not in NOTIFY_CHANNELS:
            errs.append(f"{where}: channel must be one of {', '.join(NOTIFY_CHANNELS)}")
        if not str(p.get("url", "")).strip():
            errs.append(f"{where}: url is required")
    elif t == "http":
        if str(p.get("method", "GET")).upper() not in HTTP_METHODS:
            errs.append(f"{where}: method must be one of {', '.join(HTTP_METHODS)}")
        if not str(p.get("url", "")).strip():
            errs.append(f"{where}: url is required")
        if p.get("body_type", "none") not in BODY_TYPES:
            errs.append(f"{where}: body_type must be one of {', '.join(BODY_TYPES)}")
        for key in ("headers", "query", "extract"):
            if not isinstance(p.get(key, {}), dict):
                errs.append(f"{where}: {key} must be an object")
        for name, path in (p.get("extract") or {}).items():
            try:
                parse_path(str(path))
            except TemplateError as exc:
                errs.append(f"{where}: extract {name}: {exc}")
        try:
            if not 1 <= float(p.get("timeout", 15)) <= MAX_HTTP_TIMEOUT:
                raise ValueError
        except (TypeError, ValueError):
            errs.append(f"{where}: timeout must be between 1 and {MAX_HTTP_TIMEOUT} seconds")
    return errs


def ancestors(node_id: str, edges: list[dict]) -> set[str]:
    parents: dict[str, set[str]] = {}
    for e in edges:
        parents.setdefault(e["to"], set()).add(e["from"])
    seen: set[str] = set()
    stack = [node_id]
    while stack:
        for p in parents.get(stack.pop(), ()):
            if p not in seen:
                seen.add(p)
                stack.append(p)
    return seen


def validate(graph: Any) -> dict:
    """Return the normalised graph, or raise GraphError listing every problem."""
    if not isinstance(graph, dict):
        raise GraphError(["graph must be an object"])
    nodes, edges = graph.get("nodes"), graph.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise GraphError(["graph needs a nodes list and an edges list"])
    if len(nodes) > MAX_NODES:
        raise GraphError([f"at most {MAX_NODES} nodes"])

    errs: list[str] = []
    by_id: dict[str, dict] = {}
    for n in nodes:
        if not isinstance(n, dict):
            errs.append("every node must be an object")
            continue
        nid = str(n.get("id", ""))
        if not _ID.match(nid):
            errs.append(f"bad node id {nid!r} (lowercase letters, digits, _; start with a letter)")
            continue
        if nid in by_id:
            errs.append(f"duplicate node id {nid}")
            continue
        if n.get("type") not in NODE_TYPES:
            errs.append(f"node {nid}: unknown type {n.get('type')!r}")
            continue
        try:
            retry = int(n.get("retry", 0) or 0)
        except (TypeError, ValueError):
            retry = -1
        if not 0 <= retry <= MAX_RETRY:
            errs.append(f"node {nid}: retry must be between 0 and {MAX_RETRY}")
        pos = n.get("position") or [0, 0]
        by_id[nid] = {
            "id": nid, "type": n["type"], "label": str(n.get("label") or NODE_TYPES[n["type"]]["label"])[:80],
            "position": [float(pos[0]), float(pos[1])] if isinstance(pos, (list, tuple)) and len(pos) == 2 else [0, 0],
            "params": n.get("params") or {}, "retry": max(retry, 0),
            "continue_on_error": bool(n.get("continue_on_error", False)),
        }

    triggers = [n for n in by_id.values() if n["type"] == "trigger"]
    if len(triggers) != 1:
        errs.append("a workflow needs exactly one Trigger node")

    clean_edges, seen_edges = [], set()
    for e in edges:
        if not isinstance(e, dict):
            errs.append("every edge must be an object")
            continue
        src, dst, out = str(e.get("from", "")), str(e.get("to", "")), str(e.get("output", "main"))
        if src not in by_id or dst not in by_id:
            errs.append(f"edge {src}->{dst} references a missing node")
            continue
        if out not in NODE_TYPES[by_id[src]["type"]]["outputs"]:
            errs.append(f"edge {src}->{dst}: node {src} has no output {out!r}")
            continue
        if by_id[dst]["type"] == "trigger":
            errs.append(f"edge {src}->{dst}: nothing can lead into the Trigger")
            continue
        if src == dst:
            errs.append(f"edge {src}->{dst} loops onto itself")
            continue
        if (src, out, dst) not in seen_edges:
            seen_edges.add((src, out, dst))
            clean_edges.append({"from": src, "output": out, "to": dst})

    # Cycle check (Kahn).
    indeg = {nid: 0 for nid in by_id}
    for e in clean_edges:
        indeg[e["to"]] += 1
    queue = [nid for nid, d in indeg.items() if d == 0]
    visited = 0
    while queue:
        cur = queue.pop()
        visited += 1
        for e in clean_edges:
            if e["from"] == cur:
                indeg[e["to"]] -= 1
                if indeg[e["to"]] == 0:
                    queue.append(e["to"])
    if visited != len(by_id):
        errs.append("the workflow has a loop; workflows must flow in one direction")

    for n in by_id.values():
        errs += _params_errors(n)

    if not errs:
        for n in by_id.values():
            ups = ancestors(n["id"], clean_edges)
            refs = list(references(n["params"]))
            if n["type"] in ("trigger", "if"):
                refs += [str(c.get("field", "")) for c in n["params"].get("conditions", [])]
            for ref in refs:
                try:
                    parts = parse_path(ref)
                except TemplateError as exc:
                    errs.append(f"node {n['id']}: {exc}")
                    continue
                if parts[0] == "steps":
                    target = parts[1] if len(parts) > 1 else None
                    if target not in by_id:
                        errs.append(f"node {n['id']}: {{{{ {ref} }}}} refers to unknown node {target!r}")
                    elif target not in ups:
                        errs.append(f"node {n['id']}: {{{{ {ref} }}}} uses node {target}, which does not run before it")

    if errs:
        raise GraphError(errs)
    return {"nodes": list(by_id.values()), "edges": clean_edges}


def trigger_node(graph: dict) -> dict:
    return next(n for n in graph["nodes"] if n["type"] == "trigger")


def trigger_event(graph: dict) -> str:
    return trigger_node(graph)["params"].get("event", "alert.created")


_LEGACY_AI_FIELDS = {"ai_verdict", "ai_confidence"}


def from_legacy(trigger_conditions: dict | None, actions: list[dict]) -> dict:
    """Build a linear graph from an old playbook (trigger conditions + ordered actions).

    Old playbooks ran on alert creation and again after AI triage; the converted
    one runs once, after triage when it looks at the AI verdict, else on creation.
    Each step keeps going on failure, as the old engine did.
    """
    tc = trigger_conditions or {}
    conds = tc.get("conditions", []) or []
    event = "alert.triaged" if any(c.get("field") in _LEGACY_AI_FIELDS for c in conds) else "alert.created"
    nodes = [{"id": "trigger", "type": "trigger", "label": "Trigger", "position": [0, 0],
              "params": {"event": event, "match": tc.get("match", "all"), "conditions": conds}}]
    edges = []
    prev = "trigger"
    for i, a in enumerate(sorted(actions, key=lambda x: x.get("order_index", 0))):
        p = a.get("params") or {}
        t = a.get("action_type")
        if t == "enrich_ioc":
            node = {"type": "enrich", "params": {"indicator": "{{ trigger.source_ip }}"}}
        elif t == "send_webhook":
            node = {"type": "notify", "params": {"channel": "webhook", "url": p.get("url", ""), "message": ""}}
        elif t == "create_case":
            conv = lambda s: str(s).replace("{alert_title}", "{{ trigger.rule_title }}").replace("{alert_id}", "{{ trigger.alert_id }}")
            node = {"type": "case", "params": {
                "operation": "create_case",
                "title": conv(p.get("title_template", "SOAR: {alert_title}")),
                "description": conv(p.get("description_template", "Auto-created from alert {alert_id}."))}}
        elif t == "suppress_alert":
            node = {"type": "case", "params": {"operation": "suppress", "entity_type": p.get("entity_type", "ip"),
                                                "reason": p.get("reason", "Automated SOAR suppression")}}
        elif t == "add_note":
            node = {"type": "case", "params": {"operation": "add_note",
                                                "content": p.get("content", "Automated SOAR action fired.")}}
        elif t == "isolate_agent":
            node = {"type": "response", "params": {"operation": "isolate_host"}}
        elif t == "block_ip":
            node = {"type": "response", "params": {"operation": "block_ip", "ip": p.get("ip") or "{{ trigger.source_ip }}",
                                                    "duration_seconds": p.get("duration_seconds", 3600)}}
        else:
            continue
        nid = f"step_{i + 1}"
        node.update({"id": nid, "label": NODE_TYPES[node["type"]]["label"], "position": [260 * (len(nodes)), 0],
                     "retry": 0, "continue_on_error": True})
        nodes.append(node)
        edges.append({"from": prev, "output": "main", "to": nid})
        prev = nid
    return {"nodes": nodes, "edges": edges}
