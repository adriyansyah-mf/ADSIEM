# tests/worker/test_lateral_graph.py
"""Lateral movement graph (worker/worker/lateral.py): which events are remote
hops, the agent's own address, and the alerts its findings raise."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker import behavior, lateral  # noqa: E402
from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def test_remote_logins_are_hops():
    ssh = {"event.action": "login_success", "source.ip": "10.0.0.5", "user.name": "deploy"}
    assert lateral.auth_edge("linux_auth", ssh, "db-01") == ("10.0.0.5", "ssh", "deploy")
    win = {"event.action": "login_success", "source.ip": "10.0.0.7", "user.name": "svc_backup",
           "winlog.logon.type": "3"}
    assert lateral.auth_edge("windows_security", win, "fs-01") == ("10.0.0.7", "logon", "svc_backup")
    assert lateral.auth_edge("windows_security", {**win, "winlog.logon.type": "10"}, "fs-01")[1] == "rdp"
    for not_a_hop in ({**win, "winlog.logon.type": "2"}, {**win, "winlog.logon.type": "5"},
                      {**win, "source.ip": "-"}, {**win, "source.ip": "127.0.0.1"}, {**win, "source.ip": "::1"},
                      {**win, "event.action": "login_failed"}):
        assert lateral.auth_edge("windows_security", not_a_hop, "fs-01") is None
    assert lateral.auth_edge("syslog", ssh, "db-01") is None


def test_local_address_of_outbound_connections():
    assert lateral.local_address("linux_network_connect", {"source.address": "10.0.0.5"}) == "10.0.0.5"
    win = {"SourceIp": "10.0.0.9", "Initiated": "true"}
    assert lateral.local_address("windows_etw_network", win) == "10.0.0.9"
    assert lateral.local_address("windows_etw_network", {**win, "Initiated": "false"}) == ""
    assert lateral._internal("10.1.2.3") and lateral._internal("fd00::1")
    assert not lateral._internal("8.8.8.8") and not lateral._internal("127.0.0.1")


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


@pytest.mark.parametrize("event,fields,title", [
    ("behavior_lateral_new_path", {"src": "web-01", "dst": "db-01", "protocol": "ssh", "user": "deploy"},
     "New Lateral Movement Path"),
    ("behavior_lateral_fanout", {"src": "web-01", "count": 6, "protocol": "smb", "user": ""},
     "Host Fanning Out To Many New Hosts"),
    ("behavior_lateral_chain", {"src": "db-01", "dst": "dc-01", "protocol": "rdp", "user": "admin",
                                "path": "web-01 -> db-01 -> dc-01"},
     "Lateral Movement Chain Across Hosts"),
])
def test_findings_become_alerts(engines, event, fields, title):
    dec, sig = engines
    raw = behavior.line(event, **fields)
    decoded, name = dec.decode_named("siem_behavior", raw)
    assert name == "siem_behavior" and decoded["lateral.source"] == fields["src"]
    fired = {m["title"] for m in asyncio.run(sig.evaluate(dict(decoded, raw_message=raw, log_type="siem_behavior")))}
    assert title in fired
