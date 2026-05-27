#!/usr/bin/env python3
"""
Syslog receiver: UDP/TCP 514 → Redis stream siem:logs
Parses RFC 3164 and RFC 5424. Each message becomes a log entry
identical to those sent by the Go agent, with agent_id="syslog".
"""
import asyncio
import json
import os
import re
from datetime import datetime, timezone

import redis.asyncio as aioredis
import structlog

log = structlog.get_logger()

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM_KEY = os.environ.get("REDIS_STREAM_KEY", "siem:logs")
SYSLOG_AGENT_ID = os.environ.get("SYSLOG_AGENT_ID", "00000000-0000-0000-0000-000000000001")

# RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag[pid]: message
_RFC3164 = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*"
    r"(.*)$",
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424 = re.compile(
    r"^<(\d+)>(\d+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(?:\[.*?\]|-)\s*"
    r"(.*)$",
    re.DOTALL,
)

_SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp",
]


def _parse(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw:
        return None

    m = _RFC5424.match(raw)
    if m:
        pri, _ver, ts, hostname, appname, _pid, _mid, msg = m.groups()
        pri = int(pri)
        return {
            "hostname": hostname if hostname != "-" else "unknown",
            "app": appname if appname != "-" else "syslog",
            "message": msg.strip(),
            "severity": _SEVERITY_NAMES[pri & 7],
            "facility": _FACILITY_NAMES[min((pri >> 3), len(_FACILITY_NAMES) - 1)],
            "timestamp": ts,
        }

    m = _RFC3164.match(raw)
    if m:
        pri, ts, hostname, tag, _pid, msg = m.groups()
        pri = int(pri)
        return {
            "hostname": hostname,
            "app": tag,
            "message": msg.strip(),
            "severity": _SEVERITY_NAMES[pri & 7],
            "facility": _FACILITY_NAMES[min((pri >> 3), len(_FACILITY_NAMES) - 1)],
            "timestamp": ts,
        }

    return {
        "hostname": "unknown",
        "app": "syslog",
        "message": raw,
        "severity": "info",
        "facility": "user",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self._q = queue

    def datagram_received(self, data: bytes, addr):
        try:
            self._q.put_nowait(data.decode("utf-8", errors="replace"))
        except asyncio.QueueFull:
            pass

    def error_received(self, exc):
        log.warning("udp_error", error=str(exc))


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, queue: asyncio.Queue):
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            queue.put_nowait(line.decode("utf-8", errors="replace"))
    except Exception:
        pass
    finally:
        writer.close()


async def _publish_loop(queue: asyncio.Queue, redis: aioredis.Redis):
    while True:
        raw = await queue.get()
        parsed = _parse(raw)
        if not parsed:
            continue
        entry = {
            "agent_id": SYSLOG_AGENT_ID,
            "log_type": f"syslog_{parsed['facility']}",
            "raw_message": parsed["message"],
            "received_at": datetime.now(timezone.utc).isoformat(),
            "hostname": parsed["hostname"],
        }
        try:
            await redis.xadd(STREAM_KEY, {"data": json.dumps(entry)})
        except Exception as exc:
            log.error("redis_publish_failed", error=str(exc))


async def main():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    loop = asyncio.get_running_loop()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: _SyslogProtocol(queue),
        local_addr=("0.0.0.0", 514),
    )
    log.info("syslog_udp_listening", port=514)

    tcp_server = await asyncio.start_server(
        lambda r, w: _tcp_handler(r, w, queue),
        "0.0.0.0", 514,
    )
    log.info("syslog_tcp_listening", port=514)

    log.info("syslog_receiver_started", redis=REDIS_URL, stream=STREAM_KEY)

    try:
        await asyncio.gather(
            _publish_loop(queue, redis),
            tcp_server.serve_forever(),
        )
    finally:
        transport.close()
        tcp_server.close()


if __name__ == "__main__":
    asyncio.run(main())
