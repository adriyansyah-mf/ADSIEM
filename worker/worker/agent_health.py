# worker/worker/agent_health.py
"""Agent health events: the platform's own log type for agent tampering.

The server (heartbeats) and the worker (agent monitor) write these into the
log stream like any agent line, so they are decoded (decoders/siem_agent.yaml),
searchable, and turned into alerts by ordinary Sigma rules
(rules/siem_agent_*.yaml) — dedup, notifications and AI triage included.

    event=agent_stopped reason=service_stop version=1.7.0
    event=agent_offline last_seen="2026-10-19T10:00:00+00:00"
    event=agent_integrity_changed file=binary previous=<sha256> current=<sha256> version=1.7.0
"""
from datetime import datetime, timezone

LOG_TYPE = "siem_agent"


def _quote(value) -> str:
    s = str(value)
    if s and not any(c in s for c in ' "=\\'):
        return s
    # decoder_engine._parse_kv unescapes \" and \\ inside quotes
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def health_line(event: str, **fields) -> str:
    parts = [f"event={event}"]
    parts += [f"{k}={_quote(v)}" for k, v in fields.items() if v is not None and v != ""]
    return " ".join(parts)


def health_event(event: str, *, agent_id, group_id: str, hostname: str, **fields) -> dict:
    """A log-stream entry, in the shape the ingest API enqueues."""
    return {
        "agent_id": str(agent_id) if agent_id else "",
        "group_id": group_id or "default",
        "hostname": hostname or "unknown",
        "log_type": LOG_TYPE,
        "raw_message": health_line(event, **fields),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "location": "siem",
    }
