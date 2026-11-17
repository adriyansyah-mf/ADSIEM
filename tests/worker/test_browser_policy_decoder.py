# tests/worker/test_browser_policy_decoder.py
"""The agent's managed browser policy lines (agent/internal/browserpolicy
Line) decode with decoders/browser_policy.yaml."""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As browserpolicy.Line formats it (see TestControllerReportsOnlyChanges).
LINE = ('event=browser_policy mode=on set="chrome:DnsOverHttpsMode,chrome:ExtensionSettings,firefox:DNSOverHTTPS" '
        'kept="edge:DnsOverHttpsMode" removed="" errors=""')


def test_browser_policy_line_decodes():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted([open(f).read() for f in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))],
                                   key=lambda c: yaml.safe_load(c).get("priority", 100)))
    event, name = dec.decode_named("browser_policy", LINE)
    assert name == "browser_policy"
    assert event["browser_policy.mode"] == "on"
    assert "firefox:DNSOverHTTPS" in event["browser_policy.set"]
    assert event["browser_policy.kept"] == "edge:DnsOverHttpsMode"
    assert event["event.action"] == "browser_policy"
