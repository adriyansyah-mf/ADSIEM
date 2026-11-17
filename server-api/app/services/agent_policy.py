# server-api/app/services/agent_policy.py
"""Per-group protection policy and exclusions for Linux and Windows agents.

A group without a policy uses the "default" group's; without that, the
built-in defaults (everything on, malware action from the global setting).
Agents get `policy_version` in heartbeats and fetch the policy when it
changes (POST /api/ingest/policy); the worker reads the alert exclusions."""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AgentPolicy

DEFAULT_GROUP = "default"
CACHE_SECONDS = 30.0
MAX_EXCLUSIONS = 500

Scope = Literal["prevention", "malware", "yara", "ransomware", "script", "ml", "ioa", "alerts"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_SCHEDULE = re.compile(r"^(mon|tue|wed|thu|fri|sat|sun|daily) ([01][0-9]|2[0-3]):[0-5][0-9]$")
_ABS = re.compile(r"^(/|[A-Za-z]:\\)")
_USB_ID = re.compile(r"^([0-9A-F]{4}):([0-9A-F]{4})(?::([^\s:]{1,128}))?$")
MAX_USB_ALLOW = 500
MAX_ROLLBACK_PATHS = 50


class Exclusion(BaseModel):
    """kind: path_prefix (a file or anything under a folder), image (the
    program: full path, or a file name to match it in any folder), sha256,
    command_line (substring). scopes: what it turns off for matches."""
    kind: Literal["path_prefix", "image", "sha256", "command_line"]
    value: str = Field(min_length=1, max_length=1024)
    scopes: list[Scope] = Field(min_length=1)
    comment: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _check(self):
        v = self.value.strip()
        if self.kind == "sha256":
            v = v.lower()
            if not _SHA256.match(v):
                raise ValueError("sha256 exclusions need 64 hex characters")
        if self.kind == "path_prefix" and not _ABS.match(v):
            raise ValueError("path_prefix exclusions need an absolute path (/opt/app/ or C:\\Tools\\)")
        if self.kind == "command_line" and len(v) < 4:
            raise ValueError("command_line exclusions need at least 4 characters")
        self.value = v
        self.scopes = sorted(set(self.scopes))
        return self


class PolicySettings(BaseModel):
    prevention_enabled: bool = True          # execution prevention rules and known-malware blocking
    malware_action: Literal["off", "detect", "block"] | None = None  # None: the global setting
    yara_on_access: bool = True
    ransomware_mode: Literal["off", "report", "stop"] = "stop"
    ransomware_isolate: bool = False
    # ransomware rollback (agent/internal/rollback): auto keeps hourly snapshots of the user data
    # folders (rollback_paths; empty = each user's Documents, Desktop, Pictures, Downloads, and
    # /srv, /var/www on Linux) and puts back what a process changed once ransomware protection
    # stopped it. Costs disk (5 GB at most by default), so off by default.
    ransomware_rollback: Literal["off", "auto"] = "off"
    rollback_paths: list[str] = Field(default_factory=list, max_length=MAX_ROLLBACK_PATHS)
    notify_user: bool = True                 # pop-ups for the signed-in user (Windows)
    # scripts scanned with the YARA rules as they run (Windows: AMSI content; Linux: interpreters'
    # code); block stops the process on a high or critical match
    script_scan: Literal["off", "detect", "block"] = "detect"
    # static ML on scanned files (EMBER model for PE, heuristic for ELF):
    # block quarantines files over the malicious threshold
    ml_action: Literal["off", "detect", "block"] = "detect"
    # YARA match on a file (agent/internal/yarascan): detect reports it; quarantine also locks the
    # file when the rule's severity is at least yara_quarantine_level, and stops the program that
    # dropped it when that program itself runs from temp, downloads or shared memory
    yara_action: Literal["detect", "quarantine"] = "detect"
    yara_quarantine_level: Literal["high", "critical"] = "critical"
    # Linux: a program outside the OS's directories is held at exec until the agent scanned it
    # (fanotify, fail open after 3 s); Windows scans each new program as it starts
    exec_scan: Literal["on", "off"] = "on"
    # indicators of attack: behaviour chains in a process tree (agent/internal/ioa),
    # reported as alerts; detect only for now (nothing is stopped)
    ioa: Literal["off", "detect"] = "detect"
    # IP IoC blocklist (app/services/ip_blocks.py): detect reports connections to listed
    # addresses as ioc_match; block also drops them (nftables on Linux, WFP on Windows)
    ip_ioc: Literal["off", "detect", "block"] = "block"
    # Windows App Control (WDAC) built from the execution prevention rules: block rules
    # stop programs before they run (audit only logs what enforce would block); Linux
    # already blocks before execution with BPF LSM, so this is Windows only
    app_control: Literal["off", "audit", "enforce"] = "off"
    # USB mass storage (agent/internal/usbguard): audit reports every stick or external disk
    # plugged in; block cuts off those not on usb_allow (Linux: USB authorization, Windows:
    # eject). Keyboards, mice and other USB classes are never touched.
    usb_storage: Literal["off", "audit", "block"] = "audit"
    # VID:PID (every unit of a model) or VID:PID:SERIAL (one unit), hex as lsusb / Device Manager show it
    usb_allow: list[str] = Field(default_factory=list, max_length=MAX_USB_ALLOW)
    # managed browser policies (agent/internal/browserpolicy): on turns DNS over HTTPS off
    # (Chrome, Edge, Chromium, Brave, Firefox) and blocks extensions asking for the proxy
    # permission (VPN/proxy extensions, Chromium browsers), so the web block holds in the
    # browser; an administrator's own values are kept. off removes the agent's ones.
    browser_policy: Literal["off", "on"] = "off"
    # DNS sinkhole (agent/internal/dnssink): on blocks every subdomain of the web block's manual
    # and alert domains (at most 500) through a resolver on the agent that the OS sends only
    # those names to: an NRPT rule on Windows, routing domains in systemd-resolved on Linux.
    dns_sinkhole: Literal["off", "on"] = "off"
    # scheduled file scans (agent local time): quick every day at HH:MM;
    # full on "<mon..sun> HH:MM" or "daily HH:MM". "" is off.
    quick_scan_time: str = Field(default="", max_length=32)
    full_scan_schedule: str = Field(default="", max_length=32)
    exclusions: list[Exclusion] = Field(default_factory=list, max_length=MAX_EXCLUSIONS)

    @field_validator("quick_scan_time")
    @classmethod
    def _quick(cls, v: str) -> str:
        v = v.strip()
        if v and not _HHMM.match(v):
            raise ValueError("quick_scan_time: HH:MM (24 h) or empty")
        return v

    @field_validator("full_scan_schedule")
    @classmethod
    def _full(cls, v: str) -> str:
        v = " ".join(v.lower().split())
        if v and not _SCHEDULE.match(v):
            raise ValueError("full_scan_schedule: '<mon..sun|daily> HH:MM' or empty")
        return v

    @field_validator("rollback_paths")
    @classmethod
    def _rollback_paths(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            p = raw.strip()
            if not p:
                continue
            absolute = p.startswith("/") or (len(p) >= 3 and p[1] == ":" and p[2] in "\\/") or p.startswith("\\\\")
            if not absolute or len(p) > 400 or any(c in p for c in "\0\n\r*?"):
                raise ValueError(f"rollback_paths: {raw!r} is not an absolute folder path (no wildcards)")
            if p in ("/", "\\") or (len(p) <= 3 and p[1:2] == ":"):
                raise ValueError(f"rollback_paths: {raw!r} is a whole drive; name the folders to keep")
            if p not in out:
                out.append(p)
        return out

    @field_validator("usb_allow")
    @classmethod
    def _usb_allow(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            entry = raw.strip()
            m = _USB_ID.match(entry.upper())
            if not m:
                raise ValueError(f"usb_allow: {raw!r} is not VID:PID or VID:PID:SERIAL (hex, e.g. 0781:5567)")
            vid, pid = m.group(1), m.group(2)
            serial = entry.split(":", 2)[2] if m.group(3) else None  # keep the serial as written
            norm = f"{vid}:{pid}" + (f":{serial}" if serial else "")
            if norm.upper() not in {x.upper() for x in out}:
                out.append(norm)
        return out

    @field_validator("exclusions")
    @classmethod
    def _unique(cls, v: list[Exclusion]) -> list[Exclusion]:
        seen, out = set(), []
        for e in v:
            key = (e.kind, e.value.lower())
            if key not in seen:
                seen.add(key)
                out.append(e)
        return out


def version_of(settings: dict) -> str:
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]


_cache: dict[str, tuple[float, dict]] = {}


def invalidate() -> None:
    _cache.clear()


async def effective(db: AsyncSession, group_id: str | None) -> dict:
    """{"group": the group whose policy applies, "settings": validated dict, "version": hash}."""
    group_id = group_id or DEFAULT_GROUP
    now = time.monotonic()
    hit = _cache.get(group_id)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    row = await db.get(AgentPolicy, group_id)
    source = group_id
    if row is None and group_id != DEFAULT_GROUP:
        row, source = await db.get(AgentPolicy, DEFAULT_GROUP), DEFAULT_GROUP
    if row is None:
        source = "built-in"
    settings = PolicySettings.model_validate(row.settings if row else {}).model_dump()
    out = {"group": source, "settings": settings, "version": version_of(settings)}
    _cache[group_id] = (now, out)
    return out
