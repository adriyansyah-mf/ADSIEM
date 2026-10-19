# server-api/app/services/agent_tamper.py
"""Tamper signals from agent heartbeats (see worker/worker/agent_health.py)."""
from app.models.models import Agent

_FILES = (("binary", "binary_sha256"), ("config", "config_sha256"))


def check_integrity(agent: Agent, version: str | None, reported: dict | None) -> tuple[dict, list[dict]]:
    """Compare a heartbeat's hashes with the agent's baseline.

    Returns (agent column updates, agent_integrity_changed event fields). The
    first report, and every new agent version (an upgrade replaces the binary),
    set the baseline silently; after that each changed hash is one event and
    becomes the new baseline, so a change alerts once."""
    if not reported:
        return {}, []
    hashes = {col: (reported.get(col) or None) for _, col in _FILES}
    baseline_unset = all(getattr(agent, col) is None for _, col in _FILES)
    if baseline_unset or agent.integrity_version != version:
        return {**hashes, "integrity_version": version}, []
    updates, events = {}, []
    for name, col in _FILES:
        old, new = getattr(agent, col), hashes[col]
        if new is None or new == old:
            continue  # a file the agent couldn't hash this time is not a change
        updates[col] = new
        if old is not None:
            events.append({"file": name, "previous": old, "current": new, "version": version})
    return updates, events
