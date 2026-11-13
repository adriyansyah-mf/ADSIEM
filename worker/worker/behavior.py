# worker/worker/behavior.py
"""Behaviour baselines from the agents' own telemetry (Linux eBPF / ss
fallback and Windows ETW alike), per host, in Redis:

- rare parent → child: a process pair this host never ran, that at most
  RARE_FLEET hosts of the group ever ran (Office → cmd, a web server → sh).
- new rare executable: a program started from a user-writable folder (temp,
  downloads, a profile, /tmp, /dev/shm) that this host never ran and no other
  host of the group runs.
- beaconing: one program connecting to the same external address and port
  at a steady rhythm (at least BEACON_MIN_CONNECTIONS, median gap
  10 s - 1 h, jitter at most BEACON_MAX_JITTER): what C2 implants do.

A host learns for `behavior_learning_hours` (platform setting, default 72)
from its first telemetry before first-seen detections report anything.
Findings go back into the log stream as siem_behavior lines, so decoders,
Sigma rules (rules/behavior_*.yaml), dedup and AI triage handle them like
any detection. Never raises into the pipeline (the caller also guards)."""
from __future__ import annotations

import ipaddress
import statistics
import time
from datetime import datetime, timezone

import structlog

from worker.config import REDIS_STREAM_KEY
from worker.settings_cache import get_setting

log = structlog.get_logger()

LOG_TYPE = "siem_behavior"
DEFAULT_LEARNING_HOURS = 72
RARE_FLEET = 2                 # a parent → child pair this many hosts ran is still rare
MAX_HOST_SET = 50_000          # first-seen memory per host and kind; past it nothing new is learned
BASELINE_TTL = 90 * 86400
BEACON_MIN_CONNECTIONS = 8
BEACON_KEEP = 30
BEACON_MIN_GAP, BEACON_MAX_GAP = 10.0, 3600.0
BEACON_MAX_JITTER = 0.2        # median absolute deviation of the gaps / their median
BEACON_FLEET_MAX = 3           # beyond this many hosts, the destination is a fleet service (updates, monitoring)
BEACON_REPORT_EVERY = 86400
NOISY_PORTS = {53, 123, 137, 138, 5353}  # DNS, NTP, NetBIOS, mDNS: periodic by design

PROCESS_TYPES = {"linux_process_exec", "windows_etw_process"}
# the SIEM agent itself: agents before 1.27.1 reported their own connections to
# the server (a feedback loop); they are never beaconing, UEBA or lateral input
AGENT_PROGRAMS = {"siem-agent", "siem-agent.exe", "agent"}
NETWORK_TYPES = {"linux_network_connect", "linux_network_snapshot", "windows_etw_network"}

_USER_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/", "/root/",
                  "\\users\\", "\\programdata\\", "\\windows\\temp\\", "\\$recycle.bin\\", "\\perflogs\\")


def _k(*parts) -> str:
    return "siem:bhv:" + ":".join(str(p) for p in parts)


def _base(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _quote(value) -> str:
    s = str(value)
    if s and not any(c in s for c in ' "=\\'):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def line(event: str, **fields) -> str:
    return " ".join([f"event={event}"] + [f"{k}={_quote(v)}" for k, v in fields.items() if v not in (None, "")])


def user_writable(path: str) -> bool:
    p = path.lower().replace("/", "\\") if ":" in path[:3] else path.lower()
    return any(m in p for m in _USER_WRITABLE)


def beacon_stats(times: list[float]) -> tuple[float, float] | None:
    """(median gap, jitter) of connection times, or None when they are not a steady rhythm."""
    ts = sorted(set(round(t, 1) for t in times))
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 1.0]
    if len(gaps) < BEACON_MIN_CONNECTIONS - 1:
        return None
    med = statistics.median(gaps)
    if not BEACON_MIN_GAP <= med <= BEACON_MAX_GAP:
        return None
    jitter = statistics.median(abs(g - med) for g in gaps) / med
    return (med, jitter) if jitter <= BEACON_MAX_JITTER else None


def _event_time(decoded: dict, fallback: float) -> float:
    raw = decoded.get("event.start") or decoded.get("@timestamp") or ""
    if raw:
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return fallback


def _external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


async def _setting_int(key: str, default: int) -> int:
    try:
        return int(await get_setting(key, str(default)) or default)
    except (TypeError, ValueError):
        return default


class Behavior:
    """Per-event detectors; `emit` takes (event, fields) findings to push."""

    def __init__(self, redis, now=time.time):
        self.r = redis
        self.now = now

    async def mark_seen(self, agent: str) -> None:
        """Start the host's learning clock at its first telemetry (one cheap SET NX per event)."""
        await self.r.set(_k("host", agent, "first"), str(self.now()), nx=True, ex=BASELINE_TTL)

    async def learning(self, agent: str) -> bool:
        """Whether the host is still learning; read only when something new turned up."""
        key = _k("host", agent, "first")
        now = self.now()
        first = float(await self.r.get(key) or now)
        await self.r.expire(key, BASELINE_TTL)
        return now - first < await _setting_int("behavior_learning_hours", DEFAULT_LEARNING_HOURS) * 3600

    async def _first_seen(self, agent: str, group: str, kind: str, value: str) -> tuple[bool, int]:
        """(new on this host, hosts of the group that saw it, this one included)."""
        host_key, fleet_key = _k(kind, agent), _k(kind + "fleet", group, value)
        await self.r.sadd(fleet_key, agent)
        await self.r.expire(fleet_key, BASELINE_TTL)
        fleet = int(await self.r.scard(fleet_key))
        if await self.r.sismember(host_key, value):
            return False, fleet
        if int(await self.r.scard(host_key)) >= MAX_HOST_SET:
            return False, fleet
        await self.r.sadd(host_key, value)
        await self.r.expire(host_key, BASELINE_TTL)
        return True, fleet

    async def process(self, agent: str, group: str, decoded: dict) -> list[tuple[str, dict]]:
        image = str(decoded.get("Image") or decoded.get("process.executable") or "").strip()
        parent = str(decoded.get("ParentImage") or decoded.get("process.parent.name") or "").strip()
        if not image:
            return []
        await self.mark_seen(agent)
        out = []
        if parent:
            pair = f"{_base(parent)}>{_base(image)}"
            new, fleet = await self._first_seen(agent, group, "pc", pair)
            if new and fleet <= RARE_FLEET and not await self.learning(agent):
                out.append(("behavior_rare_parent_child", {
                    "parent": parent, "image": image, "pair": pair, "fleet_hosts": fleet,
                    "command_line": decoded.get("CommandLine") or decoded.get("process.command_line") or ""}))
        if user_writable(image):
            new, fleet = await self._first_seen(agent, group, "exe", image.lower())
            if new and fleet <= 1 and not await self.learning(agent):
                out.append(("behavior_new_rare_executable", {
                    "image": image, "parent": parent, "fleet_hosts": fleet}))
        return out

    async def network(self, agent: str, group: str, log_type: str, decoded: dict,
                      received: float, raw: str = "") -> list[tuple[str, dict]]:
        conn = outbound_connection(log_type, decoded, raw)
        if conn is None:
            return []
        dst, port_n, proc = conn
        if port_n in NOISY_PORTS or not _external(dst):
            return []
        key = _k("bc", agent, f"{proc.lower()}|{dst}|{port_n}")
        await self.r.lpush(key, str(_event_time(decoded, received)))
        await self.r.ltrim(key, 0, BEACON_KEEP - 1)
        await self.r.expire(key, BEACON_REPORT_EVERY)
        times = [float(t) for t in await self.r.lrange(key, 0, -1)]
        stats = beacon_stats(times)
        if stats is None:
            return []
        if not await self.r.set(_k("bcflag", agent, f"{proc.lower()}|{dst}|{port_n}"), "1",
                                nx=True, ex=BEACON_REPORT_EVERY):
            return []  # already reported today
        fleet_key = _k("bcfleet", group, f"{dst}|{port_n}")
        await self.r.sadd(fleet_key, agent)
        await self.r.expire(fleet_key, 7 * 86400)
        fleet = int(await self.r.scard(fleet_key))
        if fleet > BEACON_FLEET_MAX:
            return []  # many hosts call it on a timer: an update or monitoring service
        med, jitter = stats
        return [("behavior_beaconing", {
            "image": proc, "destination": dst, "port": port_n, "interval_s": round(med, 1),
            "jitter": round(jitter, 3), "connections": len(times), "fleet_hosts": fleet})]


def outbound_connection(log_type: str, decoded: dict, raw: str = "") -> tuple[str, int, str] | None:
    """(destination, port, program) of an outbound connection line, or None
    (inbound, not a connection, or incomplete). Shared with UEBA host features."""
    if log_type not in NETWORK_TYPES:
        return None
    if log_type == "windows_etw_network" and str(decoded.get("Initiated", "true")).lower() != "true":
        return None  # inbound: the remote side picks the rhythm
    if log_type == "linux_network_snapshot":
        dst, port, proc = _ss_peer(raw)
    else:
        dst = str(decoded.get("destination.ip") or decoded.get("destination.address") or "")
        port = str(decoded.get("destination.port") or "")
        proc = str(decoded.get("process.name") or decoded.get("Image") or "")
    try:
        port_n = int(port)
    except ValueError:
        return None
    if not dst or not proc or _base(proc) in AGENT_PROGRAMS:
        return None
    return dst, port_n, proc


def external(ip: str) -> bool:
    return _external(ip)


def _ss_peer(raw: str) -> tuple[str, str, str]:
    """Peer address, port and process of an `ss -tunapH` line (the snapshot
    fallback's decoder keeps no fields): netid state recv-q send-q local peer process."""
    cols = raw.split()
    if len(cols) < 6 or ":" not in cols[5]:
        return "", "", ""
    peer, port = cols[5].rsplit(":", 1)
    peer = peer.strip("[]").split("%", 1)[0]
    proc = ""
    rest = " ".join(cols[6:])
    if '(("' in rest:
        proc = rest.split('(("', 1)[1].split('"', 1)[0]
    return peer, port, proc


async def observe(redis, *, log_type: str, decoded: dict, agent_id, group_id: str, hostname: str,
                  received: float, raw: str = "") -> list[str]:
    """Run the detectors for one event and push their findings; returns the events pushed."""
    if not agent_id or log_type not in PROCESS_TYPES | NETWORK_TYPES:
        return []
    b = Behavior(redis)
    agent, group = str(agent_id), group_id or "default"
    if log_type in PROCESS_TYPES:
        found = await b.process(agent, group, decoded)
    else:
        found = await b.network(agent, group, log_type, decoded, received, raw)
    for event, fields in found:
        await redis.xadd(REDIS_STREAM_KEY, {
            "agent_id": agent, "group_id": group, "hostname": hostname or "unknown", "log_type": LOG_TYPE,
            "raw_message": line(event, **fields),
            "received_at": datetime.fromtimestamp(received, timezone.utc).isoformat(),
            "location": "siem"})
        log.info("behavior_finding", finding=event, agent_id=agent, **{k: v for k, v in fields.items()
                                                                     if k in ("pair", "image", "destination")})
    return [e for e, _ in found]
