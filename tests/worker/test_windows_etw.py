# tests/worker/test_windows_etw.py
"""The agent's ETW sensor lines (agent/internal/winsensor) decode like Sysmon's
and reach the windows/process_creation, network_connection and dns_query
rules, so hosts without Sysmon are covered by the same Sigma rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As TestProcessStartJoinsBothHalves (agent/internal/winsensor) formats it.
ETW_PROCESS = ('EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="2336" '
               'Image="C:\\Windows\\System32\\sc.exe" CommandLine="sc.exe stop SIEMAgent" User="WIN01\\alice" '
               'IntegrityLevel="High" ParentProcessId="1012" ParentImage="C:\\Windows\\System32\\cmd.exe" '
               'ParentCommandLine="cmd.exe"')
ETW_NETWORK = ('EventID=3 Channel="ETW" Provider="Microsoft-Windows-Kernel-Network" ProcessId="5040" '
               'Image="C:\\Users\\alice\\AppData\\Local\\Temp\\beacon.exe" User="WIN01\\alice" Protocol="tcp" '
               'Initiated="true" SourceIp="10.1.0.103" SourcePort="50177" DestinationIp="203.0.113.9" '
               'DestinationPort="4444" DestinationIsIpv6="false"')
ETW_DNS = ('EventID=22 Channel="ETW" Provider="Microsoft-Windows-DNS-Client" ProcessId="5040" '
           'Image="C:\\Users\\alice\\AppData\\Local\\Temp\\beacon.exe" User="WIN01\\alice" '
           'QueryName="c2.example.onion" QueryType="1" QueryStatus="0" QueryResults="203.0.113.9;"')


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


def _titles(eng, event):
    return [m["title"] for m in asyncio.run(eng.evaluate(event))]


def _engine(*rules):
    eng = SigmaEngine()
    eng.load_from_yaml_list(list(rules))
    assert not eng.load_errors, eng.load_errors
    return eng


@pytest.mark.parametrize("log_type,line,decoder,fields", [
    ("windows_etw_process", ETW_PROCESS, "win_etw_process_created",
     {"Image": "C:\\Windows\\System32\\sc.exe", "CommandLine": "sc.exe stop SIEMAgent",
      "process.parent.name": "C:\\Windows\\System32\\cmd.exe", "user.name": "WIN01\\alice",
      "IntegrityLevel": "High", "event.category": "process", "event.action": "process_created"}),
    ("windows_etw_network", ETW_NETWORK, "win_etw_network_connection",
     {"destination.ip": "203.0.113.9", "destination.port": "4444", "Initiated": "true",
      "network.transport": "tcp", "event.action": "network_connection"}),
    ("windows_etw_dns", ETW_DNS, "win_etw_dns_query",
     {"dns.question.name": "c2.example.onion", "QueryName": "c2.example.onion", "event.action": "dns_query"}),
])
def test_etw_lines_decode_with_sysmon_fields(decoders, log_type, line, decoder, fields):
    event, name = decoders.decode_named(log_type, line)
    assert name == decoder
    for key, value in fields.items():
        assert event.get(key) == value, (key, event.get(key))


def test_shipped_process_rule_fires_on_etw(decoders):
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    event, _ = decoders.decode_named("windows_etw_process", ETW_PROCESS)
    assert "SIEM Agent Tampering Command" in _titles(sig, dict(event, raw_message=ETW_PROCESS))
    # Image|endswith '\sc.exe' needs the full path the sensor joins in: a bare
    # name (the kernel logger alone) would not match
    bare = ETW_PROCESS.replace('Image="C:\\Windows\\System32\\sc.exe"', 'Image="sc.exe"')
    event, _ = decoders.decode_named("windows_etw_process", bare)
    assert "SIEM Agent Tampering Command" not in _titles(sig, dict(event, raw_message=bare))


NET_RULE = """
title: Outbound to 4444
logsource: {product: windows, category: network_connection}
detection:
  selection:
    Initiated: 'true'
    DestinationPort: 4444
  condition: selection
"""
DNS_RULE = """
title: Onion Lookup
logsource: {product: windows, category: dns_query}
detection:
  selection:
    QueryName|endswith: '.onion'
  condition: selection
"""
PROC_RULE = """
title: Service Control
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\\\sc.exe'
  condition: selection
"""


def test_each_etw_log_type_reaches_only_its_category():
    eng = _engine(NET_RULE, DNS_RULE, PROC_RULE)
    hits = {log_type: _titles(eng, {"log_type": log_type, "raw_message": line})
            for log_type, line in (("windows_etw_process", ETW_PROCESS), ("windows_etw_network", ETW_NETWORK),
                                   ("windows_etw_dns", ETW_DNS))}
    assert hits == {"windows_etw_process": ["Service Control"], "windows_etw_network": ["Outbound to 4444"],
                    "windows_etw_dns": ["Onion Lookup"]}
