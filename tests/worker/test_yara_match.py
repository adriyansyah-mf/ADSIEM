# tests/worker/test_yara_match.py
"""The agent's on-access YARA match lines (agent/internal/yarascan) decode
with decoders/yara_match.yaml and raise the alert of the rule's severity."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def match_line(severity, path='/var/www/html/up/s.php'):
    # As yarascan.MatchLine formats it (see TestMatchLineQuoting).
    return (f'event=yara_match rule="webshell_php" namespace="builtin \\"pack\\"" severity={severity} '
            f'file="{path}" sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 size=27 '
            f'tags="php,webshell" strings="$s1@6" trigger=on_access description="PHP webshell indicators"')


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


def test_match_line_decodes(decoders):
    event, name = decoders.decode_named("yara_match", match_line("critical"))
    assert name == "yara_match"
    assert event["yara.rule"] == "webshell_php"
    assert event["yara.namespace"] == 'builtin "pack"'
    assert event["yara.severity"] == "critical"
    assert event["file.path"] == "/var/www/html/up/s.php"
    assert event["file.hash.sha256"].startswith("9f86d0")
    assert event["yara.strings"] == "$s1@6"
    assert event["event.category"] == "malware"
    assert event["event.action"] == "yara_match"


def test_windows_path_survives(decoders):
    event, _ = decoders.decode_named("yara_match", match_line("high", path="C:\\\\Users\\\\bob\\\\Downloads\\\\x.exe"))
    assert event["file.path"] == "C:\\Users\\bob\\Downloads\\x.exe"


@pytest.mark.parametrize("severity,title", [
    ("critical", "YARA Rule Matched On Endpoint (Critical)"),
    ("high", "YARA Rule Matched On Endpoint (High)"),
    ("medium", "YARA Rule Matched On Endpoint (Medium)"),
    ("low", "YARA Rule Matched On Endpoint (Low)"),
])
def test_alert_per_severity(decoders, rules, severity, title):
    line = match_line(severity)
    event, _ = decoders.decode_named("yara_match", line)
    matches = asyncio.run(rules.evaluate(dict(event, raw_message=line, log_type="yara_match", hostname="web01")))
    assert [(m["title"], m["level"]) for m in matches] == [(title, severity)]


def test_other_log_types_do_not_fire(decoders, rules):
    line = match_line("high")
    event, _ = decoders.decode_named("linux_auth", line)
    matches = asyncio.run(rules.evaluate(dict(event or {}, raw_message=line, log_type="linux_auth")))
    assert not [m for m in matches if m["title"].startswith("YARA")]
