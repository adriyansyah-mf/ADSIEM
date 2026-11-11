# tests/worker/test_ioa.py
"""The agent's ioa_detection lines (agent/internal/ioa) decode and raise the
alert for their rule; every agent rule has its own Sigma rule."""
import asyncio
import glob
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
AGENT_RULES = open(os.path.join(ROOT, "agent/internal/ioa/rules.go")).read()
AGENT_IDS = re.findall(r'ID: "(ioa_[a-z_]+)"', AGENT_RULES)


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def line(rule="ioa_office_child_internet", severity="high", technique="T1566.001"):
    # As ioa.Line formats it: \\ and \" escaped inside quotes.
    return (f'event=ioa action=detected rule={rule} severity={severity} tactic=initial-access technique={technique} '
            'title="Office app started a script host that reached the internet" '
            'image="C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe" pid=200 '
            'command_line="powershell -nop -w hidden -c \\"iex(...)\\"" user="CORP\\\\alice" '
            'anchor_image="C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE" anchor_pid=100 '
            'anchor_command_line="WINWORD.EXE /n invoice.docm" parent_image="C:\\\\Windows\\\\explorer.exe" '
            'chain="office app: winword.exe (pid 100) > child launcher: powershell.exe (pid 200) > '
            'internet connection: powershell.exe -> 203.0.113.9:443"')


def test_agent_rules_found():
    assert len(AGENT_IDS) >= 10 and len(set(AGENT_IDS)) == len(AGENT_IDS)


def test_decodes(decoders):
    ev, name = decoders.decode_named("ioa_detection", line())
    assert name == "ioa_detection" and ev["event.action"] == "ioa"
    assert ev["ioa.rule"] == "ioa_office_child_internet" and ev["ioa.severity"] == "high"
    assert ev["process.executable"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert ev["process.command_line"] == 'powershell -nop -w hidden -c "iex(...)"'
    assert ev["ioa.anchor_image"].endswith("WINWORD.EXE") and ev["process.parent.executable"].endswith("explorer.exe")
    assert ev["user.name"] == "CORP\\alice" and ev["process.pid"] == "200"
    assert "203.0.113.9:443" in ev["ioa.chain"]


def _matches(decoders, rules, raw):
    ev, _ = decoders.decode_named("ioa_detection", raw)
    flat = {**ev, "log_type": "ioa_detection", "raw_message": raw, "hostname": "h", "group_id": "default"}
    return asyncio.run(rules.evaluate(flat))


@pytest.mark.parametrize("rule_id", AGENT_IDS)
def test_every_agent_rule_has_its_sigma_rule(decoders, rules, rule_id):
    sev = re.search(rf'ID: "{rule_id}",.*?Severity: "(\w+)"', AGENT_RULES, re.S).group(1)
    tech = re.search(rf'ID: "{rule_id}",.*?Technique: "(T[\d.]+)"', AGENT_RULES, re.S).group(1)
    hits = _matches(decoders, rules, line(rule_id, sev, tech))
    assert len(hits) == 1, [h.get("title") for h in hits]
    h = hits[0]
    assert h["title"].startswith("IOA: ") and h["title"] != "IOA: Behaviour chain detected"
    assert h["level"] == sev
    assert any(t == f"attack.{tech.lower()}" for t in h.get("tags", [])), h.get("tags")


def test_unknown_rule_falls_back(decoders, rules):
    hits = _matches(decoders, rules, line("ioa_from_a_newer_agent"))
    assert [h["title"] for h in hits] == ["IOA: Behaviour chain detected"]
