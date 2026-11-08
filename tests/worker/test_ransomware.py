# tests/worker/test_ransomware.py
"""Ransomware lines from agent/internal/ransomguard decode and alert: a
confirmed detection is critical, a changed canary high, a retired canary
medium, an unconfirmed heuristic (a big build, a bulk copy) stays telemetry.
Repeats of one incident are suppressed."""
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
CANARY = ('detection=canary confirmed=true response=killed Canary="/home/alice/.siem-canary.pdf" FileAction=rename '
          'Image="/tmp/.x/crypt" Comm="crypt" PID=42 PPID=1 User=1000 Killed=3 Isolated=true')
EXT = ('detection=extension_change confirmed=true response=killed Files=20 Extension=".locked" '
       'TargetFilename="/srv/share/doc019.txt.locked" Entropy=7.98 Image="/tmp/ransom.test" Comm="ransom.test" '
       'PID=2186 PPID=2180 User=0 Killed=1 Isolated=false')
UNCONFIRMED = ('detection=mass_modify confirmed=false response=none Files=800 TargetFilename="/root/.cache/x/trim.txt" '
               'Entropy=0.00 Image="/usr/local/bin/bulkcopy" Comm="bulkcopy" PID=2190 PPID=2190 User=1000 Isolated=false')
CHANGED = 'detection=canary_changed confirmed=false response=none Canary="C:\\\\Users\\\\bob\\\\Documents\\\\.siem-canary.pdf" Isolated=false'
# As TestPeriodicCheckEncryptedCanaryIsolates: the periodic check found a canary
# encrypted, no process known; the host was isolated.
CHANGED_ENCRYPTED = ('detection=canary_changed confirmed=true response=isolated '
                     'Canary="C:\\\\Users\\\\bob\\\\Documents\\\\.siem-canary.docx" Isolated=true')
# As TestGuardInplaceEncryptionKills: files encrypted over themselves.
INPLACE = ('detection=inplace_modify confirmed=true response=killed Files=50 '
           'TargetFilename="C:\\\\Users\\\\bob\\\\Documents\\\\d1\\\\f49.docx" Entropy=7.95 '
           'Image="C:\\\\Users\\\\bob\\\\Downloads\\\\invoice.exe" Comm="invoice.exe" PID=66 PPID=0 User=0 Killed=1 Isolated=false')
INPLACE_UNCONFIRMED = ('detection=inplace_modify confirmed=false response=none Files=50 '
                       'TargetFilename="C:\\\\Users\\\\bob\\\\Pictures\\\\IMG_0059.jpg" Entropy=7.95 '
                       'Image="C:\\\\Program Files\\\\Editor\\\\editor.exe" Comm="editor.exe" PID=67 PPID=0 User=0 Isolated=false')
RETIRED = ('detection=canary_retired confirmed=false response=none Canary="/srv/app/.siem-canary.pdf" '
           'Image="/usr/bin/rsync" Comm="rsync" PID=900 PPID=1 User=0 Isolated=false')


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
    assert event["ransomware.canary"] == "/home/alice/.siem-canary.pdf"
    assert event["ransomware.killed"] == "3" and event["ransomware.isolated"] == "true"
    event, _ = decoders.decode_named("ransomware_activity", EXT)
    assert event["ransomware.extension"] == ".locked" and event["ransomware.entropy"] == "7.98"
    assert event["file.path"].endswith(".locked")
    event, _ = decoders.decode_named("ransomware_activity", CHANGED)
    assert event["ransomware.canary"] == "C:\\Users\\bob\\Documents\\.siem-canary.pdf"
    event, _ = decoders.decode_named("ransomware_activity", CHANGED_ENCRYPTED)
    assert event["ransomware.confirmed"] == "true" and event["ransomware.response"] == "isolated"
    assert event["ransomware.isolated"] == "true" and "process.executable" not in event
    event, _ = decoders.decode_named("ransomware_activity", INPLACE)
    assert event["ransomware.detection"] == "inplace_modify" and event["ransomware.files"] == "50"


@pytest.mark.parametrize("line,expected", [
    (CANARY, [("Ransomware Activity On Endpoint", "critical")]),
    (EXT, [("Ransomware Activity On Endpoint", "critical")]),
    (UNCONFIRMED, []),
    (CHANGED, [("Ransomware Canary File Changed", "high")]),
    # Encrypted canary, no process: the critical alert alone, not a second high one.
    (CHANGED_ENCRYPTED, [("Ransomware Activity On Endpoint", "critical")]),
    (INPLACE, [("Ransomware Activity On Endpoint", "critical")]),
    (INPLACE_UNCONFIRMED, []),
    (RETIRED, [("Ransomware Canary Retired", "medium")]),
])
def test_alerts(decoders, rules, line, expected):
    event, _ = decoders.decode_named("ransomware_activity", line)
    view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="fs01")
    assert [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))] == expected


def test_encrypted_canary_is_one_critical_alert(decoders):
    """A canary found encrypted with no process is the critical alert only: the
    high "changed" rule is for clear-text changes (a fresh engine, so no earlier
    case's suppression hides a second alert)."""
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/ransomware_*.yaml"))
    event, _ = decoders.decode_named("ransomware_activity", CHANGED_ENCRYPTED)
    view = dict(event, raw_message=CHANGED_ENCRYPTED, log_type="ransomware_activity", hostname="fs09")
    assert [(m["title"], m["level"]) for m in asyncio.run(sig.evaluate(view))] == [
        ("Ransomware Activity On Endpoint", "critical")]
    event, _ = decoders.decode_named("ransomware_activity", CHANGED)
    view = dict(event, raw_message=CHANGED, log_type="ransomware_activity", hostname="fs09")
    assert [(m["title"], m["level"]) for m in asyncio.run(sig.evaluate(view))] == [
        ("Ransomware Canary File Changed", "high")]


def test_repeats_suppressed(decoders):
    """Every canary an encryptor touches is one incident; another binary or host is not."""
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/ransomware_*.yaml"))

    def titles(line, host="fs01"):
        event, _ = decoders.decode_named("ransomware_activity", line)
        view = dict(event, raw_message=line, log_type="ransomware_activity", hostname=host)
        return [m["title"] for m in asyncio.run(sig.evaluate(view))]

    assert titles(CANARY) == ["Ransomware Activity On Endpoint"]
    assert titles(CANARY.replace("/home/alice/", "/root/")) == []
    assert titles(EXT) == ["Ransomware Activity On Endpoint"]
    assert titles(CANARY, host="fs02") == ["Ransomware Activity On Endpoint"]
    assert titles(CHANGED) == ["Ransomware Canary File Changed"]
    assert titles(CHANGED.replace("bob", "carol")) == []
