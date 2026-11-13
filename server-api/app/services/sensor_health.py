# server-api/app/services/sensor_health.py
"""Telemetry sensor tamper detection from heartbeats (agent/internal/sensorstat).

Each heartbeat carries, per sensor (etw, procexec, netwatch, linsensor),
whether it runs, how many events it delivered into the agent's buffer and
how many it lost. Counted on the agent, so a slow server never makes a sensor
look silent. Compared with the previous heartbeat's state (kept in Redis):

- agent_sensor_stopped: a sensor that ran no longer does (or vanished)
  while the agent keeps heartbeating: its session was stopped, its programs
  detached, or the process lost the privilege.
- agent_sensor_silent: a sensor that delivered events delivered none for
  `silence` seconds while the agent heartbeats: blinded without being stopped
  (ETW provider disabled, eBPF link detached, events filtered). Once per
  silence; cleared when events flow again.
- agent_sensor_events_lost: at least LOST_MIN events lost since the last
  heartbeat (kernel buffers, a full queue): flooding or starving the sensor.
  At most once per LOST_REPORT_EVERY per sensor.

A counter going down is an agent restart: the baseline starts over.
rules/siem_agent_sensor_*.yaml turn the events into alerts."""
from __future__ import annotations

import json

STATE_KEY = "siem:agent:sensors:{}"
STATE_TTL = 86400
DEFAULT_SILENCE_MINUTES = 60
MIN_BASELINE = 20          # a sensor that delivered fewer events has no rhythm to miss
LOST_MIN = 100
LOST_REPORT_EVERY = 3600
MAX_SENSORS = 16


def evaluate(prev: dict | None, current: dict, now: float, silence: int) -> tuple[dict, list[tuple[str, dict]]]:
    """(new state, [(event, fields)]) for one heartbeat's sensor_health."""
    prev = prev or {}
    state: dict = {}
    events: list[tuple[str, dict]] = []
    for name, cur in current.items():
        running, count, lost = bool(cur.get("running")), int(cur.get("events") or 0), int(cur.get("lost") or 0)
        old = prev.get(name)
        st = {"running": running, "events": count, "lost": lost, "changed_at": now, "silent": False,
              "lost_reported_at": None}
        if old is None:
            state[name] = st
            continue
        restarted = count < old["events"] or lost < old["lost"]
        if restarted:
            state[name] = st
            if old["running"] and not running:
                events.append(("agent_sensor_stopped", {"sensor": name, "error": cur.get("error") or ""}))
            continue
        st["lost_reported_at"] = old.get("lost_reported_at")
        if count > old["events"]:
            st["changed_at"] = now
        else:
            st["changed_at"] = old["changed_at"]
            st["silent"] = old.get("silent", False)
        if old["running"] and not running:
            events.append(("agent_sensor_stopped", {"sensor": name, "error": cur.get("error") or ""}))
        elif running and silence > 0 and count == old["events"] and count >= MIN_BASELINE \
                and not st["silent"] and now - st["changed_at"] >= silence:
            st["silent"] = True
            events.append(("agent_sensor_silent", {
                "sensor": name, "silent_minutes": int((now - st["changed_at"]) // 60), "events": count}))
        delta = lost - old["lost"]
        last = st["lost_reported_at"]
        if delta >= LOST_MIN and (last is None or now - last >= LOST_REPORT_EVERY):
            st["lost_reported_at"] = now
            events.append(("agent_sensor_events_lost", {"sensor": name, "lost": delta, "lost_total": lost}))
        state[name] = st
    for name, old in prev.items():
        if name not in current and old.get("running"):
            events.append(("agent_sensor_stopped", {"sensor": name, "error": "no longer reported"}))
    return state, events


async def check(redis, agent_id, current: dict, now: float, silence_minutes: int) -> list[tuple[str, dict]]:
    """Load the previous state, evaluate, save; the events to enqueue."""
    key = STATE_KEY.format(agent_id)
    try:
        prev = json.loads(await redis.get(key) or "null")
    except (TypeError, ValueError):
        prev = None
    state, events = evaluate(prev if isinstance(prev, dict) else None, current, now, max(silence_minutes, 0) * 60)
    await redis.set(key, json.dumps(state), ex=STATE_TTL)
    return events
