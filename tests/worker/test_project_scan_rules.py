"""project_scan lines from the agent (agent/internal/projscan Lines) alert on
their findings by severity; the summary line and clean scans don't alert."""
import asyncio
import glob
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
COMMON = ' trigger=git_clone dir="/home/ana/test-task" origin="https://github.com/acme/test-task.git" image="/usr/bin/git"'
SUMMARY = ('event=project_scan verdict=suspicious severity=high' + COMMON +
           ' files=4 findings=1 truncated=false top=".vscode/tasks.json: task \\"eslint-check\\" runs curl"')
HIGH = ('event=project_scan_finding severity=high check=vscode_autorun' + COMMON +
        ' file=".vscode/tasks.json" detail="task \\"eslint-check\\" runs when the folder is opened and runs curl"')
MEDIUM = ('event=project_scan_finding severity=medium check=js_loader' + COMMON +
          ' file="lib/a.js" detail="obfuscated code"')
CLEAN = ('event=project_scan verdict=clean severity=none' + COMMON + ' files=4 findings=0 truncated=false top=""')


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def _alerts(decoders, rules, line):
    event, _ = decoders.decode_named("project_scan", line)
    view = dict(event, raw_message=line, log_type="project_scan", hostname="dev-01")
    return {m["title"]: m["level"] for m in asyncio.run(rules.evaluate(view))}


def test_finding_line_decodes(decoders):
    fields, name = decoders.decode_named("project_scan", HIGH)
    assert name == "project_scan"
    assert fields["event.action"] == "project_scan_finding" and fields["event.severity"] == "high"
    assert fields["file.directory"] == "/home/ana/test-task" and fields["file.path"] == ".vscode/tasks.json"
    assert fields["url.original"] == "https://github.com/acme/test-task.git"
    assert fields["message"] == 'task "eslint-check" runs when the folder is opened and runs curl'
    assert fields["project.check"] == "vscode_autorun"


@pytest.mark.parametrize("line,level", [(HIGH, "high"), (MEDIUM, "medium")])
def test_findings_alert_by_severity(decoders, rules, line, level):
    alerts = {t: lv for t, lv in _alerts(decoders, rules, line).items() if t.startswith("Malicious-Looking Project")}
    assert list(alerts.values()) == [level]


@pytest.mark.parametrize("line", [SUMMARY, CLEAN])
def test_summary_and_clean_lines_do_not_alert(decoders, rules, line):
    assert not any(t.startswith("Malicious-Looking Project") for t in _alerts(decoders, rules, line))
