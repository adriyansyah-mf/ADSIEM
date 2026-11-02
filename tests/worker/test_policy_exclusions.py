# tests/worker/test_policy_exclusions.py
"""Alert exclusions from group policies (worker/policy_exclusions.py): what
each kind matches, and the group / default-group choice."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import policy_exclusions as pe

SHA = "ab" * 32


def test_kinds():
    procexp_driver = {"ImageLoaded": "C:\\Users\\bob\\AppData\\Local\\Temp\\PROCEXP152.SYS", "EventID": "6"}
    assert pe.matches({"kind": "path_prefix", "value": "C:\\Users\\bob\\AppData\\Local\\Temp\\procexp152.sys"},
                      procexp_driver)
    assert pe.matches({"kind": "path_prefix", "value": "/opt/backup/"}, {"TargetFilename": "/opt/backup/x.tar"})
    assert not pe.matches({"kind": "path_prefix", "value": "/opt/backup/"}, {"TargetFilename": "/opt/backup2/x"})
    assert pe.matches({"kind": "image", "value": "veeam.exe"}, {"Image": "C:\\Program Files\\Veeam\\VEEAM.EXE"})
    assert pe.matches({"kind": "image", "value": "/usr/bin/restic"}, {"process.executable": "/usr/bin/restic"})
    assert not pe.matches({"kind": "image", "value": "/usr/bin/restic"}, {"process.executable": "/tmp/restic"})
    assert pe.matches({"kind": "image", "value": "procdump64.exe"}, {"SourceImage": "C:\\t\\procdump64.exe"})
    assert pe.matches({"kind": "sha256", "value": SHA}, {"file.hash.sha256": SHA.upper()})
    assert pe.matches({"kind": "sha256", "value": SHA}, {"Hashes": f"MD5=00,SHA256={SHA.upper()}"})
    assert pe.matches({"kind": "command_line", "value": "--nightly-backup"},
                      {"CommandLine": "rsync -a --NIGHTLY-backup /srv /mnt"})
    assert not pe.matches({"kind": "command_line", "value": "--nightly-backup"}, {"CommandLine": "rsync -a"})
    assert not pe.matches({"kind": "unknown", "value": "x"}, {"Image": "x"})


def test_group_then_default(monkeypatch):
    pe._cache = (10**12, {
        "blue": [{"kind": "image", "value": "scanner.exe", "scopes": ["alerts"]}],
        "default": [{"kind": "image", "value": "veeam.exe", "scopes": ["alerts"]}],
    })
    try:
        ev_scanner, ev_veeam = {"Image": "C:\\x\\scanner.exe"}, {"Image": "C:\\x\\veeam.exe"}
        assert asyncio.run(pe.excluded(ev_scanner, "blue"))["value"] == "scanner.exe"
        assert asyncio.run(pe.excluded(ev_veeam, "blue")) is None  # blue has its own policy
        assert asyncio.run(pe.excluded(ev_veeam, "red"))["value"] == "veeam.exe"  # red falls back to default
        assert asyncio.run(pe.excluded(ev_scanner, None)) is None
    finally:
        pe._cache = None
