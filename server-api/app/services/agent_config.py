# server-api/app/services/agent_config.py
"""The part of the agents' config.yaml a group policy may set (settings.agent_config).

The agent decodes it into config.Overlay (agent/internal/config/overlay.go) and
drops every key it does not know, so the section and field names here must be
its JSON names exactly (tests/server-api/test_agent_config.py checks them
against the Go source). Every field is optional: unset means "keep the agent's
local value", while an explicit false, 0 or [] overrides it. Unset fields are
never sent: dump_overlay leaves them out, so the agent never sees a null.

The rest of config.yaml stays local (identity and token, state paths, live
response, anti-tamper, update keys); log sources and FIM paths are already
managed per agent through the heartbeat. server.url must be https here; the
agent also refuses a URL whose host differs from its local one, which only it
can check."""
from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Go int is 32 bits on 32-bit builds: a larger number would fail the agent's
# whole policy decode, not just this field.
_INT_MAX = 2**31 - 1
_INT64_MAX = 2**63 - 1
MAX_LIST = 500

Count = Annotated[int, Field(ge=0, le=_INT_MAX)]
Positive = Annotated[int, Field(gt=0, le=_INT_MAX)]
Bytes64 = Annotated[int, Field(gt=0, le=_INT64_MAX)]
Item = Annotated[str, Field(min_length=1, max_length=1024)]
TextList = Annotated[list[Item], Field(max_length=MAX_LIST)]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerOverlay(_Section):
    url: str | None = Field(None, max_length=2048)
    # The worker marks an agent offline after 300 s without a heartbeat.
    heartbeat_interval: int | None = Field(None, ge=10, le=240)

    @field_validator("url")
    @classmethod
    def _https(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        try:
            u = urlsplit(v)
            ok = u.scheme == "https" and bool(u.hostname)
        except ValueError:
            ok = False
        if not ok:
            raise ValueError("server.url: an https URL (the agent keeps it only if the host is its own)")
        return v


class AgentOverlay(_Section):
    buffer_size: Positive | None = None


class FimOverlay(_Section):
    enabled: bool | None = None


class FirewallOverlay(_Section):
    enabled: bool | None = None
    # agent/internal/firewall selectBackend
    backend: Literal["auto", "nft", "netsh", "noop"] | None = None
    dry_run: bool | None = None
    protected_ips: TextList | None = None
    isolation_release_after_offline_minutes: Count | None = None


class NetwatchOverlay(_Section):
    enabled: bool | None = None
    snapshot_fallback: bool | None = None


class ETWOverlay(_Section):
    mode: Literal["auto", "on", "off"] | None = None
    disabled_events: list[Literal["file", "image"]] | None = None  # config.Load accepts these groups


class DetectOverlay(_Section):
    enabled: bool | None = None
    rules: TextList | None = None
    max_blocked: Count | None = None             # 0: the agent's default
    max_blocks_per_minute: Count | None = None   # 0: the agent's default


class LinuxSensorOverlay(_Section):
    disabled: bool | None = None
    disabled_events: TextList | None = None


class RansomwareOverlay(_Section):
    # No canary_dirs or canary_names: they are paths the agent writes as
    # SYSTEM/root, which the server must not choose.
    disabled: bool | None = None
    canary_visible: bool | None = None
    allow_images: TextList | None = None


class YaraOverlay(_Section):
    watch_paths: TextList | None = None
    max_file_size_mb: int | None = Field(None, ge=1, le=1024)


class MemorySweepOverlay(_Section):
    disabled: bool | None = None
    interval_minutes: int | None = Field(None, ge=1, le=1440)


class EvidenceOverlay(_Section):
    # The overlay comes after config.Load filled the defaults, so a 0 here
    # would reach evidence.Options.Validate, which wants positive sizes.
    enabled: bool | None = None
    max_bytes: Bytes64 | None = None
    segment_bytes: Bytes64 | None = None
    reserved_bytes: Annotated[int, Field(ge=0, le=_INT64_MAX)] | None = None
    max_event_bytes: Positive | None = None


class DisabledOverlay(_Section):
    disabled: bool | None = None


class AgentConfigOverlay(_Section):
    server: ServerOverlay | None = None
    agent: AgentOverlay | None = None
    fim: FimOverlay | None = None
    firewall: FirewallOverlay | None = None
    netwatch: NetwatchOverlay | None = None
    etw: ETWOverlay | None = None
    detect: DetectOverlay | None = None
    linux_sensor: LinuxSensorOverlay | None = None
    ransomware: RansomwareOverlay | None = None
    yara: YaraOverlay | None = None
    memory_sweep: MemorySweepOverlay | None = None
    evidence: EvidenceOverlay | None = None
    prevention: DisabledOverlay | None = None
    notify: DisabledOverlay | None = None
    project_scan: DisabledOverlay | None = None
    update: DisabledOverlay | None = None


def _prune(v):
    """Drop None values and the sections left empty; lists stay, [] included."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if x is None:
                continue
            x = _prune(x)
            if x != {}:
                out[k] = x
        return out
    return v


def dump_overlay(overlay: AgentConfigOverlay | None) -> dict | None:
    """The overlay as stored and sent: only the fields set, None when nothing is."""
    if overlay is None:
        return None
    return _prune(overlay.model_dump(exclude_none=True)) or None


def config_version_of(overlay: dict | None) -> str:
    """Hash of the overlay alone ("" for none), separate from the policy version:
    agents restart only when this one changes."""
    clean = _prune(overlay or {})
    if not clean:
        return ""
    return hashlib.sha256(json.dumps(clean, sort_keys=True).encode()).hexdigest()[:16]
