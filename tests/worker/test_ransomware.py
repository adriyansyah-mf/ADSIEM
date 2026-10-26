# tests/worker/test_ransomware.py
"""Ransomware lines from agent/internal/ransomguard decode and alert: a
confirmed detection is critical, a changed canary high, an unconfirmed
heuristic (a big build, a bulk copy) stays telemetry."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As TestGuardCanaryKillsAndReports / TestRansomwareEndToEnd / TestFalsePositives produce them.
CANARY = ('detection=canary confirmed=true response=killed Canary="/home/alice/!siem-canary.pdf" FileAction=rename '
          'Image="/tmp/.x/crypt" Comm="crypt" PID=42 PPID=1 User=1000 Killed=3 Isolated=true')
EXT = ('detection=extension_change confirmed=true response=killed Files=20 Extension=".locked" '
       'TargetFilename="/srv/share/doc019.txt.locked" Entropy=7.98 Image="/tmp/ransom.test" Comm="ransom.test" '
       'PID=2186 PPID=2180 User=0 Killed=1 Isolated=false')
UNCONFIRMED = ('detection=mass_modify confirmed=false response=none Files=800 TargetFilename="/root/.cache/x/trim.txt" '
               'Entropy=0.00 Image="/usr/local/bin/bulkcopy" Comm="bulkcopy" PID=2190 PPID=2190 User=1000 Isolated=false')
CHANGED = 'detection=canary_changed confirmed=false response=none Canary="C:\\\\Users\\\\bob\\\\Documents\\\\!siem-canary.pdf" Isolated=false'


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


def test_decode(decoders):
    event, name = decoders.decode_named("ransomware_activity", CANARY)
    assert name == "ransomware_activity"
    assert event["ransomware.detection"] == "canary"
    assert event["ransomware.canary"] == "/home/alice/!siem-canary.pdf"
    assert event["ransomware.killed"] == "3" and event["ransomware.isolated"] == "true"
    event, _ = decoders.decode_named("ransomware_activity", EXT)
    assert event["ransomware.extension"] == ".locked" and event["ransomware.entropy"] == "7.98"
    assert event["file.path"].endswith(".locked")
    event, _ = decoders.decode_named("ransomware_activity", CHANGED)
    assert event["ransomware.canary"] == "C:\\Users\\bob\\Documents\\!siem-canary.pdf"


@pytest.mark.parametrize("line,expected", [
    (CANARY, [("Ransomware Activity On Endpoint", "critical")]),
    (EXT, [("Ransomware Activity On Endpoint", "critical")]),
    (UNCONFIRMED, []),
    (CHANGED, [("Ransomware Canary File Changed", "high")]),
])
def test_alerts(decoders, rules, line, expected):
    event, _ = decoders.decode_named("ransomware_activity", line)
    view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="fs01")
    assert [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))] == expected
