# worker/worker/lateral.py
"""Lateral movement graph: which host reaches which, how, and as whom.

Edges (src → dst, protocol) come from:
- successful logins with a remote source: SSH "Accepted ..." (linux_auth) and
  Windows 4624 logon type 3 (network) or 10 (RDP) (windows_security);
- agents' outbound connections to an internal address on a remote
  administration port (22 SSH, 445 SMB, 3389 RDP, 5985/5986 WinRM, 135 RPC).

Addresses become hostnames through what agents report as their own local
address on outbound connections (siem:lat:ip:<group>:<ip>, 7 days); unknown
ones stay addresses. Edges live in lateral_edges (one row per group, src,
dst and protocol); Redis gates the writes to once per edge per EDGE_TOUCH.

After a group's learning period (`behavior_learning_hours`, default 72) a new
edge is reported, and so are a host opening FANOUT_MIN new paths within an
hour and a chain A → B → C of new paths within CHAIN_WINDOW. Findings go into
the stream as siem_behavior lines (rules/behavior_lateral_*.yaml), so they
feed triage, SOAR and entity risk. Never raises into the pipeline."""
from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone

import structlog
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker import behavior, settings_cache
from worker.config import REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal

log = structlog.get_logger()

PORTS = {22: "ssh", 445: "smb", 3389: "rdp", 5985: "winrm", 5986: "winrm", 135: "rpc"}
AUTH_TYPES = {"linux_auth", "windows_security"}
IP_TTL = 7 * 86400
EDGE_TOUCH = 300
FANOUT_WINDOW, FANOUT_MIN, FANOUT_REPORT_EVERY = 3600, 5, 6 * 3600
CHAIN_WINDOW = 2 * 3600
MAX_USERS = 20
DEFAULT_LEARNING_HOURS = 72


def _k(*parts) -> str:
    return "siem:lat:" + ":".join(str(p) for p in parts)


def _internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return False
    return (a.is_private or a.is_link_local) and not a.is_loopback and not a.is_unspecified


def auth_edge(log_type: str, decoded: dict, hostname: str) -> tuple[str, str, str] | None:
    """(source ip, protocol, user) of a remote login to `hostname`, or None."""
    if log_type not in AUTH_TYPES or str(decoded.get("event.action", "")) != "login_success":
        return None
    src = str(decoded.get("source.ip") or "").strip()
    if not src or src in ("-", "::1") or src.startswith("127."):
        return None
    if log_type == "linux_auth":
        protocol = "ssh"
    else:
        logon = str(decoded.get("winlog.logon.type") or decoded.get("LogonType") or "")
        if logon not in ("3", "10"):
            return None  # interactive, service, batch...: not a remote hop
        protocol = "rdp" if logon == "10" else "logon"
    user = str(decoded.get("user.name") or "").strip()
    return src, protocol, user


def local_address(log_type: str, decoded: dict) -> str:
    """The agent's own address on an outbound connection line."""
    if log_type == "windows_etw_network":
        if str(decoded.get("Initiated", "true")).lower() != "true":
            return ""
        return str(decoded.get("SourceIp") or decoded.get("source.ip") or "")
    if log_type == "linux_network_connect":
        return str(decoded.get("source.address") or "")
    return ""


class Lateral:
    def __init__(self, redis, sessions=None, now=time.time):
        self.r = redis
        self.sessions = sessions or AsyncSessionLocal
        self.now = now

    async def learn_address(self, group: str, ip: str, hostname: str) -> None:
        if ip and hostname and _internal(ip):
            await self.r.set(_k("ip", group, ip), hostname, ex=IP_TTL)

    async def host_of(self, group: str, ip: str) -> str:
        return (await self.r.get(_k("ip", group, ip))) or ip

    async def learning(self, group: str) -> bool:
        key = _k("group", group, "first")
        now = self.now()
        await self.r.set(key, str(now), nx=True, ex=90 * 86400)
        first = float(await self.r.get(key) or now)
        try:
            hours = int(await settings_cache.get_setting("behavior_learning_hours", str(DEFAULT_LEARNING_HOURS))
                        or DEFAULT_LEARNING_HOURS)
        except (TypeError, ValueError):
            hours = DEFAULT_LEARNING_HOURS
        return now - first < hours * 3600

    async def observe(self, group: str, src: str, dst: str, protocol: str, user: str = "") -> list[tuple[str, dict]]:
        """Record src → dst; the findings a new path causes."""
        if not src or not dst or src == dst:
            return []
        if not await self.r.set(_k("touch", group, f"{src}|{dst}|{protocol}|{user}"), "1", nx=True, ex=EDGE_TOUCH):
            return []  # touched recently: nothing new to learn
        new = await self._upsert(group, src, dst, protocol, user)
        if not new or await self.learning(group):
            return []
        found = [("behavior_lateral_new_path", {"src": src, "dst": dst, "protocol": protocol, "user": user})]
        # fan-out: one source opening many new paths within the hour
        fan = _k("fan", group, src)
        await self.r.sadd(fan, dst)
        await self.r.expire(fan, FANOUT_WINDOW)
        count = int(await self.r.scard(fan))
        if count >= FANOUT_MIN and await self.r.set(_k("fanflag", group, src), "1", nx=True, ex=FANOUT_REPORT_EVERY):
            found.append(("behavior_lateral_fanout", {"src": src, "count": count, "protocol": protocol, "user": user}))
        # chain: the source was itself reached by a new path shortly before
        upstream = await self.r.get(_k("in", group, src))
        if upstream and upstream != dst:
            found.append(("behavior_lateral_chain", {"src": src, "dst": dst, "protocol": protocol, "user": user,
                                                     "path": f"{upstream} -> {src} -> {dst}"}))
        await self.r.set(_k("in", group, dst), src, ex=CHAIN_WINDOW)
        return found

    async def _upsert(self, group, src, dst, protocol, user) -> bool:
        """Insert or refresh the edge; True when it did not exist."""
        from worker.models import LateralEdge
        now = datetime.now(timezone.utc)
        users = [user] if user else []
        stmt = pg_insert(LateralEdge).values(group_id=group, src=src[:255], dst=dst[:255], protocol=protocol,
                                             users=users, count=1, first_seen=now, last_seen=now)
        stmt = stmt.on_conflict_do_update(
            index_elements=["group_id", "src", "dst", "protocol"],
            set_={"count": LateralEdge.count + 1, "last_seen": now,
                  # append a user not listed yet, up to MAX_USERS, oldest first
                  "users": text(
                      "CASE WHEN jsonb_array_length(excluded.users) = 0 "
                      "OR lateral_edges.users @> excluded.users "
                      f"OR jsonb_array_length(lateral_edges.users) >= {MAX_USERS} "
                      "THEN lateral_edges.users ELSE lateral_edges.users || excluded.users END")},
        ).returning(text("(xmax = 0) AS inserted"))
        async with self.sessions() as db:
            inserted = (await db.execute(stmt)).scalar_one()
            await db.commit()
        return bool(inserted)


async def observe(redis, *, log_type: str, decoded: dict, group_id: str, hostname: str, agent_id=None,
                  sessions=None) -> list[str]:
    """Learn addresses and edges from one event; push findings. Returns the events pushed."""
    group = group_id or "default"
    lat = Lateral(redis, sessions)
    found: list[tuple[str, dict]] = []
    if log_type in AUTH_TYPES:
        edge = auth_edge(log_type, decoded, hostname)
        if edge is None or not hostname:
            return []
        src_ip, protocol, user = edge
        found = await lat.observe(group, await lat.host_of(group, src_ip), hostname, protocol, user)
    elif log_type in behavior.NETWORK_TYPES:
        await lat.learn_address(group, local_address(log_type, decoded), hostname)
        conn = behavior.outbound_connection(log_type, decoded)
        if conn is None or not hostname:
            return []
        dst_ip, port, _ = conn
        protocol = PORTS.get(port)
        if protocol is None or not _internal(dst_ip):
            return []
        found = await lat.observe(group, hostname, await lat.host_of(group, dst_ip), protocol)
    else:
        return []
    for event, fields in found:
        await redis.xadd(REDIS_STREAM_KEY, {
            "agent_id": str(agent_id) if agent_id else "", "group_id": group,
            "hostname": fields.get("src") or hostname or "unknown", "log_type": behavior.LOG_TYPE,
            "raw_message": behavior.line(event, **fields),
            "received_at": datetime.now(timezone.utc).isoformat(), "location": "siem"})
        log.info("lateral_finding", finding=event, src=fields.get("src"), dst=fields.get("dst"))
    return [e for e, _ in found]
