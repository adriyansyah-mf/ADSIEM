# server-api/app/services/agent_tamper.py
"""Tamper signals from agent heartbeats (see worker/worker/agent_health.py)."""
import base64
import hashlib
import hmac

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


# ─── Uninstall token ─────────────────────────────────────────────
# Derived, not stored: HMAC of the agent id with the server's secret, so it can
# be shown again on the Agents page and the agent only ever gets its SHA-256.
# Changing JWT_SECRET changes every agent's token (agents pick it up on the
# next heartbeat).

def uninstall_token(agent_id) -> str:
    from app.core.config import settings

    mac = hmac.new(settings.JWT_SECRET.encode(), f"siem-agent-uninstall:{agent_id}".encode(), hashlib.sha256)
    raw = base64.b32encode(mac.digest()).decode()[:20]
    return "-".join(raw[i:i + 5] for i in range(0, 20, 5))


def uninstall_token_sha256(agent_id) -> str:
    return hashlib.sha256(uninstall_token(agent_id).encode()).hexdigest()


# ─── Heartbeat continuity ────────────────────────────────────────
# Each agent process sends a random session id and a rising sequence number.
# A restart starts a new session — normal. Going back to the previous session
# soon after means two processes are sending with this agent's token (a copied
# token keeping a dead agent "alive"); a sequence number going back within a
# session is a replayed heartbeat.

SESSION_SWITCH_WINDOW = 600  # seconds


def heartbeat_anomaly(state: dict, session: str | None, seq: int | None, now: float) -> tuple[dict, str | None]:
    """(new state, anomaly kind or None). state is what the previous heartbeat left."""
    if not session:
        return state, None  # agents before 1.8.0
    seq = int(seq or 0)
    last_seq = int(state.get("seq") or 0)
    current, prev = state.get("session"), state.get("prev_session")
    if session == current:
        anomaly = "replay" if seq <= last_seq else None
        return {**state, "seq": max(seq, last_seq), "at": now}, anomaly
    recent = now - float(state.get("switched_at") or 0) < SESSION_SWITCH_WINDOW
    anomaly = "duplicate_session" if session == prev and recent else None
    return {"session": session, "seq": seq, "prev_session": current or "", "switched_at": now, "at": now}, anomaly
