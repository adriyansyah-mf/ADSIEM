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
# As TestWindowsCriticalPrecursorsKillTheInitiator: IronChain's shadow-copy
# deletion; the Desktop sample (the initiator) and its tree were killed.
PRECURSOR = ('detection=precursor confirmed=true response=killed Precursor=shadow_delete '
             'CommandLine="vssadmin delete shadows /all /quiet" '
             'PrecursorImage="C:\\\\Windows\\\\System32\\\\vssadmin.exe" PrecursorPID=3200 '
             'Image="C:\\\\Users\\\\bob\\\\Desktop\\\\9f2c1e.exe" Comm="9f2c1e.exe" PID=3000 PPID=2000 User=0 '
             'Killed=3 Isolated=false')
# As TestProtectedInitiatorKillsOnlyThePrecursor / TestBootTamperIsReverted:
# from services.exe (protected), only bcdedit was killed, the change undone.
PRECURSOR_PROTECTED = ('detection=precursor confirmed=true response=killed Precursor=boot_tamper '
                       'CommandLine="bcdedit /set {default} safeboot minimal" '
                       'PrecursorImage="C:\\\\Windows\\\\System32\\\\bcdedit.exe" PrecursorPID=5200 '
                       'Image="C:\\\\Windows\\\\System32\\\\services.exe" Comm="services.exe" PID=600 PPID=500 User=0 '
                       'Killed=1 Isolated=false InitiatorProtected=true Reverted="safeboot"')
# report_only on Linux.
PRECURSOR_REPORT = ('detection=precursor confirmed=true response=none Precursor=snapshot_delete '
                    'CommandLine="lvremove -f vg0/home_snap" PrecursorImage="/usr/sbin/lvremove" PrecursorPID=1200 '
                    'Image="/tmp/.x/locker" Comm="locker" PID=1000 PPID=900 User=0 Isolated=false')
# As TestPrecursorPolicyExclusions: an admin task the group policy excludes:
# logged, not stopped, no alert.
PRECURSOR_EXCLUDED = ('detection=precursor confirmed=true response=excluded Precursor=snapshot_delete '
                      'CommandLine="lvremove -f vg0/home_snap" PrecursorImage="/usr/sbin/lvremove" PrecursorPID=1700 '
                      'Image="/usr/sbin/cron" Comm="cron" PID=1500 PPID=1 User=0 Isolated=false InitiatorProtected=true')
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


def test_decode_precursor(decoders):
    event, name = decoders.decode_named("ransomware_activity", PRECURSOR)
    assert name == "ransomware_activity"
    assert event["ransomware.detection"] == "precursor"
    assert event["ransomware.precursor"] == "shadow_delete"
    assert event["ransomware.command_line"] == "vssadmin delete shadows /all /quiet"
    assert event["ransomware.precursor_image"] == "C:\\Windows\\System32\\vssadmin.exe"
    assert event["ransomware.precursor_pid"] == "3200"
    assert event["process.executable"] == "C:\\Users\\bob\\Desktop\\9f2c1e.exe"
    assert event["ransomware.killed"] == "3"
    # the command line is the precursor's, not the initiator's: kept out of
    # process.command_line so process-creation rules do not fire on it again
    assert "process.command_line" not in event
    event, _ = decoders.decode_named("ransomware_activity", PRECURSOR_PROTECTED)
    assert event["ransomware.initiator_protected"] == "true"
    assert event["ransomware.reverted"] == "safeboot"


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
    (PRECURSOR, [("Ransomware Activity On Endpoint", "critical")]),
    (PRECURSOR_PROTECTED, [("Ransomware Activity On Endpoint", "critical")]),
    (PRECURSOR_REPORT, [("Ransomware Activity On Endpoint", "critical")]),
    (PRECURSOR_EXCLUDED, []),
])
def test_alerts(decoders, rules, line, expected):
    event, _ = decoders.decode_named("ransomware_activity", line)
    view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="fs01")
    assert [(m["title"], m["level"]) for m in asyncio.run(rules.evaluate(view))] == expected


def test_ignored_exclusion_is_decoded_and_alerts(decoders):
    """As TestCommandLineExclusionNeedsATrustedInitiator: a command-line exclusion
    matched, but the initiator runs from the Desktop: killed, alerted."""
    line = PRECURSOR + " exclusion_ignored=untrusted_initiator"
    event, _ = decoders.decode_named("ransomware_activity", line)
    assert event["ransomware.exclusion_ignored"] == "untrusted_initiator"
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="ws12")
    assert [m["title"] for m in asyncio.run(sig.evaluate(view))] == ["Ransomware Activity On Endpoint"]


def test_excluded_precursor_raises_no_alert(decoders):
    """Fresh engine: nothing is suppressed, so silence means the rule does not match."""
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    event, _ = decoders.decode_named("ransomware_activity", PRECURSOR_EXCLUDED)
    assert event["ransomware.response"] == "excluded"
    view = dict(event, raw_message=PRECURSOR_EXCLUDED, log_type="ransomware_activity", hostname="db01")
    assert asyncio.run(sig.evaluate(view)) == []
    # the same line, stopped, does alert
    killed = PRECURSOR_EXCLUDED.replace("response=excluded", "response=killed")
    event, _ = decoders.decode_named("ransomware_activity", killed)
    view = dict(event, raw_message=killed, log_type="ransomware_activity", hostname="db01")
    assert [m["title"] for m in asyncio.run(sig.evaluate(view))] == ["Ransomware Activity On Endpoint"]


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


def test_destroyed_canary_with_trusted_writer_is_critical(decoders):
    """A destroyed canary is an incident even when a trusted sync client (not
    killed: response=trusted) is among its writers."""
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    line = ('detection=canary confirmed=true response=trusted '
            'Canary="C:\\\\Users\\\\bob\\\\Documents\\\\.siem-canary.docx" FileAction=write '
            'Image="C:\\\\Program Files\\\\Microsoft OneDrive\\\\OneDrive.exe" Comm="OneDrive.exe" '
            'PID=4120 PPID=3300 User=0 Isolated=false')
    event, _ = decoders.decode_named("ransomware_activity", line)
    assert event["ransomware.response"] == "trusted"
    view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="ws08")
    assert [(m["title"], m["level"]) for m in asyncio.run(sig.evaluate(view))] == [
        ("Ransomware Activity On Endpoint", "critical")]


def test_canary_sync_raises_no_alert(decoders):
    """OneDrive (from its install location) renaming or deleting a canary while
    syncing: kept in the log, no rule fires (fresh engine: nothing suppressed)."""
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    for action in ("delete", "rename"):
        line = (f'detection=canary_sync confirmed=false response=none '
                f'Canary="C:\\\\Users\\\\bob\\\\Documents\\\\.siem-canary.pdf" FileAction={action} '
                'Image="C:\\\\Program Files\\\\Microsoft OneDrive\\\\OneDrive.exe" Comm="OneDrive.exe" '
                'PID=4120 PPID=3300 User=0 Isolated=false')
        event, name = decoders.decode_named("ransomware_activity", line)
        assert name == "ransomware_activity" and event["ransomware.detection"] == "canary_sync"
        view = dict(event, raw_message=line, log_type="ransomware_activity", hostname="ws07")
        assert asyncio.run(sig.evaluate(view)) == []


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
