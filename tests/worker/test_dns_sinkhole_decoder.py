# tests/worker/test_dns_sinkhole_decoder.py
"""The agent's DNS sinkhole lines (agent/internal/dnssink) decode with
decoders/dns_sinkhole.yaml."""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _engine():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted([open(f).read() for f in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))],
                                   key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


def test_sinkholed_query_decodes():
    # as Server.report formats it
    event, name = _engine().decode_named(
        "dns_sinkhole", 'event=dns_sinkhole name="cdn.evil.com" qtype=1 blocked="evil.com"')
    assert name == "dns_sinkhole"
    assert event["dns.question.name"] == "cdn.evil.com"
    assert event["dns_sinkhole.blocked"] == "evil.com"
    assert event["event.action"] == "dns_sinkhole"


def test_state_line_decodes():
    # as Controller.state formats it
    event, _ = _engine().decode_named(
        "dns_sinkhole", 'event=dns_sinkhole_state mode=on domains=3 routed=false '
        'error="dnssink: no per-domain DNS routing on this host"')
    assert event["event.action"] == "dns_sinkhole_state"
    assert event["dns_sinkhole.mode"] == "on"
    assert event["dns_sinkhole.routed"] == "false"
    assert "no per-domain" in event["dns_sinkhole.error"]
