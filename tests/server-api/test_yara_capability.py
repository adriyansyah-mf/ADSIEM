# tests/server-api/test_yara_capability.py
"""The full-YARA capability through a real yaracheck built from
agent/cmd/yaracheck (skipped where Go is not installed), and the activation
gates that depend on it."""
import asyncio
import shutil
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import yara_capability as cap
from app.services import yara_lifecycle as life
from app.services.yara_ruleset import fingerprint

ROOT = Path(__file__).resolve().parents[2]
GOOD = 'rule AI_t { strings: $a = "evil_marker_1" $b = "evil_marker_2" ' \
       'condition: uint32(0) == 0x464C457F and filesize < 1MB and all of them }'


@pytest.fixture(scope="module")
def yaracheck(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go is not installed; the image builds yaracheck in its own stage")
    out = tmp_path_factory.mktemp("bin") / "yaracheck"
    subprocess.run(["go", "build", "-o", str(out), "./cmd/yaracheck"], cwd=ROOT / "agent", check=True,
                   capture_output=True, timeout=300)
    return str(out)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_validation_and_scans_use_the_agent_engine(yaracheck, monkeypatch, tmp_path):
    monkeypatch.setenv("YARACHECK_PATH", yaracheck)
    cap.invalidate()
    caps = _run(cap.capabilities())
    assert caps["available"] and caps["version"] == "siem-yara/1" and "pe" in caps["modules"]
    ok = _run(cap.validate(GOOD))
    assert ok["ok"] and ok["rules"] == ["AI_t"] and ok["fingerprint"] == fingerprint(GOOD)
    bad = _run(cap.validate("rule x {\n condition: $nope\n}"))
    assert not bad["ok"] and bad["line"] >= 1 and bad["error"]
    sample = tmp_path / "s"
    sample.write_bytes(b"\x7fELF....evil_marker_1....evil_marker_2")
    clean = tmp_path / "c"
    clean.write_bytes(b"\x7fELF....evil_marker_1 only")
    scan = _run(cap.scan_files(GOOD, [str(sample), str(clean)]))
    assert scan["matched"] == 1 and scan["files"][0]["rules"] == ["AI_t"]


def test_without_the_binary_the_capability_says_so(monkeypatch):
    monkeypatch.setenv("YARACHECK_PATH", "/nonexistent/yaracheck")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    cap.invalidate()
    caps = _run(cap.capabilities())
    assert caps["available"] is False and "not installed" in caps["error"]
    with pytest.raises(cap.CapabilityError):
        _run(cap.validate(GOOD))
    cap.invalidate()


def test_activation_needs_full_mode_and_current_validation_and_test():
    rule = SimpleNamespace(content=GOOD, validation=None, test_result=None)
    assert len(life.activation_blockers(rule, "draft_only")) == 3
    fp = fingerprint(GOOD)
    rule.validation = {"ok": True, "fingerprint": fp}
    rule.test_result = {"status": "passed", "fingerprint": fp}
    assert life.activation_blockers(rule, "full") == []
    rule.content = GOOD.replace("evil_marker_2", "evil_marker_3")  # an edit voids both results
    assert life.activation_blockers(rule, "full") == ["validate the current content first",
                                                      "run a test scan on the current content first"]
    rule.content = GOOD
    rule.test_result = {"status": "failed", "fingerprint": fp}
    assert life.activation_blockers(rule, "full") == ["the last test scan did not pass"]


def test_test_scans_pick_the_artifact_by_path_style():
    assert life.artifact_for("C:\\Users\\Public\\x.exe") == "Windows.Detection.Yara"
    assert life.artifact_for("\\\\server\\share\\x") == "Windows.Detection.Yara"
    assert life.artifact_for("/tmp/.x/kworkerd") == "Linux.Detection.Yara"
    assert uuid  # (imported for readability of fixtures elsewhere)
