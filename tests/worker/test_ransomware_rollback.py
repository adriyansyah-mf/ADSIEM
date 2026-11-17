# tests/worker/test_ransomware_rollback.py
"""The agent's rollback lines (agent/internal/rollback Result.Line and
SnapshotStats.Line) decode with decoders/ransomware_rollback.yaml and raise
the rollback rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
_LOOP = asyncio.new_event_loop()

RESTORED = ('event=ransomware_rollback pid=4242 image="/tmp/locker" since=2026-11-17T08:00:00Z '
            'snapshot="2026-11-17T07:00:00Z" restored=4 displaced=3 failed=0 '
            'sample="/home/a/Documents/budget.xlsx" error=""')
NOTHING = ('event=ransomware_rollback pid=4242 image="/tmp/locker" since=2026-11-17T08:00:00Z snapshot="" '
           'restored=0 displaced=0 failed=0 sample="" error="no snapshot from before 2026-11-17T08:00:00Z"')
SNAP_OK = 'event=rollback_snapshot files=120 copied=3 linked=117 bytes=40960 skipped=0 removed=1 error=""'
SNAP_ERR = ('event=rollback_snapshot files=0 copied=0 linked=0 bytes=0 skipped=0 removed=0 '
            'error="mkdir /var/lib/siem-agent/rollback/snapshots: no space left on device"')


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def titles(engines, raw):
    dec, sig = engines
    decoded, _ = dec.decode_named("ransomware_rollback", raw)
    ev = dict(decoded, raw_message=raw, log_type="ransomware_rollback")
    return decoded, {m["title"] for m in _LOOP.run_until_complete(sig.evaluate(ev))}


def test_restore_decodes_and_alerts(engines):
    ev, t = titles(engines, RESTORED)
    assert ev["event.action"] == "ransomware_rollback" and ev["rollback.restored"] == "4"
    assert ev["process.executable"] == "/tmp/locker" and ev["file.path"] == "/home/a/Documents/budget.xlsx"
    assert t == {"Ransomware Changes Rolled Back"}


def test_nothing_restored_is_high(engines):
    ev, t = titles(engines, NOTHING)
    assert "no snapshot" in ev["error.message"]
    assert t == {"Ransomware Changes Rolled Back", "Ransomware Rollback Could Not Restore"}


def test_snapshots(engines):
    ev, t = titles(engines, SNAP_OK)
    assert ev["rollback.linked"] == "117" and t == set()
    _, t = titles(engines, SNAP_ERR)
    assert t == {"Ransomware Rollback Could Not Restore"}
