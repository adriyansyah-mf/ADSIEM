# tests/server-api/test_agent_config.py
"""The agent config overlay a group policy carries (app/services/agent_config.py):
validation, its version, and that its names match what the agent decodes
(agent/internal/config/overlay.go drops unknown keys without a word)."""
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.services.agent_config import AgentConfigOverlay, config_version_of, dump_overlay

OVERLAY_GO = Path(__file__).resolve().parents[2] / "agent" / "internal" / "config" / "overlay.go"


def test_empty_overlay_has_no_version():
    assert config_version_of(None) == "" and config_version_of({}) == ""


def test_version_ignores_unset_fields():
    a = AgentConfigOverlay.model_validate({"fim": {"enabled": False}}).model_dump(exclude_none=True)
    assert config_version_of(a) == config_version_of({"fim": {"enabled": False}})


@pytest.mark.parametrize("bad", [
    {"server": {"url": "http://siem.example.com"}},
    {"server": {"heartbeat_interval": 5}},
    {"memory_sweep": {"interval_minutes": 0}},
    {"etw": {"mode": "sometimes"}},
    {"anti_tamper": {"unlock_service": True}},   # extra="forbid"
    {"agent": {"token": "x"}},
])
def test_overlay_rejects(bad):
    with pytest.raises(ValidationError):
        AgentConfigOverlay.model_validate(bad)


@pytest.mark.parametrize("bad", [
    {"server": {"url": "https://"}},
    {"server": {"heartbeat_interval": 241}},     # the worker marks agents offline after 300 s
    {"server": {"heartbeat_interval": 3600}},
    {"ransomware": {"canary_dirs": ["C:\\Windows"]}},  # paths the agent writes as SYSTEM/root
    {"ransomware": {"canary_names": ["evil.dll"]}},
    {"memory_sweep": {"interval_minutes": 1441}},
    {"yara": {"max_file_size_mb": 0}},
    {"yara": {"max_file_size_mb": 1025}},
    {"firewall": {"backend": "iptables"}},
    {"etw": {"disabled_events": ["registry"]}},
    {"agent": {"buffer_size": 0}},
    {"detect": {"max_blocked": -1}},
    {"firewall": {"isolation_release_after_offline_minutes": -1}},
    {"evidence": {"max_bytes": 0}},
    {"evidence": {"segment_bytes": 0}},
    {"evidence": {"max_event_bytes": 0}},
    {"evidence": {"reserved_bytes": -1}},
    {"evidence": {"dir": "C:\\x"}},          # stays local
    {"fim": {"watch_paths": ["/etc"]}},      # managed per agent, not in the overlay
    {"logs": [{"path": "/var/log/x"}]},
    {"update": {"trusted_keys": ["k"]}},
])
def test_overlay_rejects_out_of_range_and_local_fields(bad):
    with pytest.raises(ValidationError):
        AgentConfigOverlay.model_validate(bad)


def test_valid_overlay_keeps_explicit_false_zero_and_empty_lists():
    raw = {"server": {"url": "https://siem.example.com:8443", "heartbeat_interval": 60},
           "firewall": {"enabled": False, "backend": "nft", "protected_ips": []},
           "etw": {"mode": "off", "disabled_events": ["file", "image"]},
           "detect": {"max_blocked": 0, "rules": []},
           "yara": {"max_file_size_mb": 64},
           "memory_sweep": {"interval_minutes": 1440},
           "evidence": {"reserved_bytes": 0},
           "prevention": {"disabled": True}}
    assert dump_overlay(AgentConfigOverlay.model_validate(raw)) == raw
    assert config_version_of(raw) != ""


def test_heartbeat_interval_bounds_and_ransomware_fields():
    for v in (10, 240):
        assert AgentConfigOverlay.model_validate({"server": {"heartbeat_interval": v}}).server.heartbeat_interval == v
    raw = {"ransomware": {"disabled": False, "canary_visible": True, "allow_images": ["backup.exe"]}}
    assert dump_overlay(AgentConfigOverlay.model_validate(raw)) == raw


def test_dump_drops_unset_fields_and_empty_sections():
    o = AgentConfigOverlay.model_validate({"fim": {}, "netwatch": {"enabled": None}, "yara": {"watch_paths": ["/x"]}})
    assert dump_overlay(o) == {"yara": {"watch_paths": ["/x"]}}
    assert dump_overlay(AgentConfigOverlay.model_validate({"fim": {}})) is None
    assert dump_overlay(None) is None
    assert config_version_of({"fim": {}, "etw": {"mode": None}}) == ""
    assert config_version_of({"fim": {"enabled": True}, "etw": {}}) == config_version_of({"fim": {"enabled": True}})


def test_version_is_order_independent_and_changes_with_values():
    a = config_version_of({"fim": {"enabled": True}, "netwatch": {"enabled": False}})
    assert a == config_version_of({"netwatch": {"enabled": False}, "fim": {"enabled": True}})
    assert a != config_version_of({"fim": {"enabled": True}, "netwatch": {"enabled": True}})
    assert re.fullmatch(r"[0-9a-f]{16}", a)


def _go_overlay_fields() -> dict[str, set[str]]:
    """section json name -> field json names, as overlay.go declares them."""
    src = OVERLAY_GO.read_text(encoding="utf-8")
    structs = {name: set(re.findall(r'json:"([a-z_]+)[,"]', body))
               for name, body in re.findall(r"type (\w+) struct \{(.*?)\n\}", src, re.S)}
    top = re.search(r"type Overlay struct \{(.*?)\n\}", src, re.S).group(1)
    return {json_name: structs[typ]
            for typ, json_name in re.findall(r'\*(\w+)\s+`json:"([a-z_]+)[,"]', top)}


def test_names_match_the_go_overlay():
    go = _go_overlay_fields()
    assert go, "overlay.go not parsed"
    py = {name: set(f.annotation.__args__[0].model_fields) for name, f in AgentConfigOverlay.model_fields.items()}
    assert py == go
