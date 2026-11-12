# worker/worker/syslog_parse.py
"""Pure parsing for the agentless syslog receiver (syslog_receiver.py).

A syslog message becomes the raw_message the decoders already know:

- RFC 3164 (``<PRI>Mmm dd hh:mm:ss host tag: msg``) loses only its PRI, so it
  reads exactly like a line the agent tails from /var/log/auth.log.
- RFC 5424 (``<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG``) is rewritten
  into that same 3164 shape, so the Linux decoders match either format.
  Structured data is dropped; the message text is kept.
- Headerless senders (FortiGate's ``<189>date=... devname=...``, CEF straight
  after the PRI) lose only the PRI.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime

MAX_MESSAGE_BYTES = 64 * 1024

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_RFC3164_TS_RE = re.compile(rf"^(?:{_MONTHS}) [ \d]\d \d\d:\d\d:\d\d ")
_ISO_TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)? ")
# hostname token after a timestamp: no '=' (FortiGate kv), and a trailing ':' or '[' makes it a tag
_HOST_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._:-]*[A-Za-z0-9]|[A-Za-z0-9]) ")
_SD_RE = re.compile(r'^(?:-|(?:\[(?:[^\]"\\]|"(?:[^"\\]|\\.)*"|\\.)*\])+)')


@dataclass(frozen=True)
class SyslogMessage:
    raw_message: str        # what the decoders see
    hostname: str | None    # from the header, None when the sender sends none
    facility: int | None
    severity: int | None


def _clean(text: str) -> str:
    return text.replace("\x00", "").rstrip("\r\n ").lstrip("\ufeff")


def _rfc5424(rest: str) -> tuple[str, str | None] | None:
    """rest = everything after '<PRI>'. Returns (3164-shaped line, hostname)."""
    if not rest.startswith("1 "):
        return None
    parts = rest[2:].split(" ", 5)
    if len(parts) < 6:
        return None
    ts, host, app, procid, _msgid, tail = parts
    sd = _SD_RE.match(tail)
    if not sd:
        return None
    msg = tail[sd.end():].lstrip(" ").lstrip("\ufeff")
    try:
        stamp = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%b %e %H:%M:%S")
    except ValueError:
        stamp = datetime.now().strftime("%b %e %H:%M:%S")
    hostname = None if host == "-" else host
    tag = "" if app == "-" else app + ("" if procid == "-" else f"[{procid}]") + ":"
    line = " ".join(p for p in (stamp, hostname or "-", tag, msg) if p)
    return line, hostname


def parse_syslog(data: bytes | str) -> SyslogMessage | None:
    """One syslog frame → SyslogMessage; None when nothing is left to decode."""
    if isinstance(data, bytes):
        data = data[:MAX_MESSAGE_BYTES].decode("utf-8", errors="replace")
    text = _clean(data)
    if not text:
        return None
    facility = severity = None
    pri = _PRI_RE.match(text)
    if pri and int(pri.group(1)) <= 191:
        facility, severity = divmod(int(pri.group(1)), 8)
        text = text[pri.end():]
    converted = _rfc5424(text) if pri else None
    if converted:
        line, hostname = converted
        return SyslogMessage(_clean(line), hostname, facility, severity) if line.strip() else None
    hostname = None
    ts = _RFC3164_TS_RE.match(text) or _ISO_TS_RE.match(text)
    if ts:
        host = _HOST_RE.match(text[ts.end():])
        if host:
            hostname = host.group(1)
    text = _clean(text)
    return SyslogMessage(text, hostname, facility, severity) if text else None


class StreamFramer:
    """TCP syslog framing (RFC 6587): octet counting ("<len> <msg>") or
    newline-delimited (LF or NUL), detected per frame. Oversized frames are
    cut at MAX_MESSAGE_BYTES and the remainder skipped."""

    def __init__(self, max_bytes: int = MAX_MESSAGE_BYTES):
        self._buf = bytearray()
        self._max = max_bytes
        self._skip = 0           # octet-counted bytes still to discard
        self._skip_line = False  # discarding an oversized line until its end

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buf.extend(chunk)
        frames: list[bytes] = []
        while self._buf:
            if self._skip:
                n = min(self._skip, len(self._buf))
                del self._buf[:n]
                self._skip -= n
                continue
            if self._skip_line:
                end = self._line_end()
                if end < 0:
                    self._buf.clear()
                    break
                del self._buf[:end + 1]
                self._skip_line = False
                continue
            if self._buf[:1].isdigit():
                space = self._buf.find(b" ", 0, 12)
                if space > 0 and self._buf[:space].isdigit() and len(self._buf) == space + 1:
                    break  # can't tell octet counting from a line yet
                # a counted frame's MSG is itself a syslog message, so it starts with '<'
                if space > 0 and self._buf[:space].isdigit() and self._buf[space + 1:space + 2] == b"<":
                    length = int(self._buf[:space])
                    if len(self._buf) - space - 1 < min(length, self._max):
                        break  # wait for the rest
                    start = space + 1
                    keep = min(length, self._max)
                    frames.append(bytes(self._buf[start:start + keep]))
                    available = len(self._buf) - start
                    consumed = min(length, available)
                    del self._buf[:start + consumed]
                    self._skip = length - consumed
                    continue
            end = self._line_end()
            if end < 0:
                if len(self._buf) > self._max:
                    frames.append(bytes(self._buf[:self._max]))
                    self._buf.clear()
                    self._skip_line = True
                break
            frame = bytes(self._buf[:end])
            del self._buf[:end + 1]
            if frame.strip(b"\r\n "):
                frames.append(frame)
        return frames

    def flush(self) -> list[bytes]:
        """At connection close: whatever is buffered is the last message."""
        rest, self._buf = bytes(self._buf), bytearray()
        return [rest] if rest.strip(b"\r\n \x00") and not self._skip and not self._skip_line else []

    def _line_end(self) -> int:
        lf, nul = self._buf.find(b"\n"), self._buf.find(b"\x00")
        ends = [i for i in (lf, nul) if i >= 0]
        return min(ends) if ends else -1


def normalize_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


@dataclass(frozen=True)
class SourceEntry:
    id: str
    name: str
    group_id: str
    log_type: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


class SourceTable:
    """Sender IP → registered source; the most specific CIDR wins.
    Unregistered senders get None and their messages are dropped."""

    def __init__(self, entries: list[SourceEntry] | None = None):
        self._entries = sorted(entries or [], key=lambda e: e.network.prefixlen, reverse=True)

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, ip: str) -> SourceEntry | None:
        try:
            addr = ipaddress.ip_address(normalize_ip(ip))
        except ValueError:
            return None
        for entry in self._entries:
            if addr.version == entry.network.version and addr in entry.network:
                return entry
        return None
