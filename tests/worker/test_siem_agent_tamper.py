# tests/worker/test_siem_agent_tamper.py
"""Agent tamper detection: health events (worker.agent_health) and tamper commands
through the shipped decoders and rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.agent_health import LOG_TYPE, health_event, health_line
from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def engines():
    import yaml
    decoders = sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decoders)
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _titles(engines, log_type, line):
    dec, sig = engines
    event, _ = dec.decode_named(log_type, line)
    matches = asyncio.run(sig.evaluate(dict(event, raw_message=line, log_type=log_type)))
    return event, [m["title"] for m in matches]


def test_health_lines_quote_what_the_kv_parser_unescapes(engines):
    line = health_line("agent_stopped", reason="service_stop", note='a "quoted" C:\\path', empty="")
    assert line == 'event=agent_stopped reason=service_stop note="a \\"quoted\\" C:\\\\path"'
    from worker.decoder_engine import _parse_kv
    assert _parse_kv(line)["note"] == 'a "quoted" C:\\path'
    ev = health_event("agent_offline", agent_id=None, group_id="blue", hostname="web01", last_seen="x")
    assert ev["log_type"] == LOG_TYPE and ev["agent_id"] == "" and ev["group_id"] == "blue"


@pytest.mark.parametrize("line,title", [
    (health_line("agent_stopped", reason="service_stop", version="1.7.0"), "SIEM Agent Stopped"),
    (health_line("agent_offline", last_seen="2026-10-19T10:00:00+00:00"), "SIEM Agent Stopped Reporting"),
    (health_line("agent_integrity_changed", file="binary", previous="a" * 64, current="b" * 64),
     "SIEM Agent Binary Modified"),
    (health_line("agent_integrity_changed", file="config", previous="a" * 64, current="b" * 64),
     "SIEM Agent Config Modified"),
])
def test_health_events_alert(engines, line, title):
    event, titles = _titles(engines, LOG_TYPE, line)
    assert event["event.category"] == "agent_health"
    assert titles == [title]


@pytest.mark.parametrize("line", [
    health_line("agent_stopped", reason="system_shutdown"),
    health_line("agent_offline_mass", count=12, hosts="a,b"),
])
def test_shutdowns_and_fleet_outages_do_not_alert(engines, line):
    assert _titles(engines, LOG_TYPE, line)[1] == []


def _sysmon(image, cmd):
    return ('EventID=1 Channel="Microsoft-Windows-Sysmon/Operational" Computer="WIN01" '
            f'Image="{image}" CommandLine="{cmd}" User="CORP\\\\bob"')


@pytest.mark.parametrize("log_type,line", [
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\sc.exe", "sc stop SIEMAgent")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\sc.exe", "sc.exe config SIEMAgent start= disabled")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\net.exe", "net stop \\\"SIEM Agent\\\"")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\taskkill.exe", "taskkill /F /IM siem-agent.exe")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                               "powershell -c Stop-Service SIEMAgent -Force")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\reg.exe",
                               "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\SIEMAgent /v Start /d 4 /f")),
    ("windows_security", 'EventID=4688 Channel="Security" Computer="WIN01" '
                         'NewProcessName="C:\\Windows\\System32\\sc.exe" CommandLine="sc delete SIEMAgent"'),
    ("linux_process_exec", "Image=/usr/bin/apt-get CommandLine=\"apt-get purge -y siem-agent\" PID=1 PPID=1 User=0"),
    ("linux_process_exec", "Image=/usr/bin/rpm CommandLine=\"rpm -e siem-agent\" PID=1 PPID=1 User=0"),
    ("linux_process_exec", "Image=/usr/bin/rm CommandLine=\"rm -f /usr/bin/siem-agent\" PID=1 PPID=1 User=0"),
])
def test_tamper_commands_alert(engines, log_type, line):
    assert "SIEM Agent Tampering Command" in _titles(engines, log_type, line)[1]


@pytest.mark.parametrize("log_type,line", [
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\sc.exe", "sc query SIEMAgent")),
    ("windows_sysmon", _sysmon("C:\\Windows\\System32\\sc.exe", "sc stop Spooler")),
    ("linux_process_exec", "Image=/usr/bin/apt-get CommandLine=\"apt-get install -y ./siem-agent_1.7.0_amd64.deb\" "
                           "PID=1 PPID=1 User=0"),
    ("linux_process_exec", "Image=/usr/bin/dpkg CommandLine=\"/usr/bin/dpkg --status-fd 46 --no-triggers --unpack "
                           "--auto-deconfigure /var/cache/apt/archives/siem-agent_1.7.0_amd64.deb\" PID=1 PPID=1 User=0"),
    ("linux_process_exec", "Image=/usr/bin/cat CommandLine=\"cat /etc/siem-agent/config.yaml\" PID=1 PPID=1 User=0"),
])
def test_queries_and_upgrades_are_not_tampering(engines, log_type, line):
    assert "SIEM Agent Tampering Command" not in _titles(engines, log_type, line)[1]


def test_windows_service_start_type_and_registry(engines):
    _, titles = _titles(engines, "windows_system",
                        'EventID=7040 Channel="System" Computer="WIN01" param1="SIEM Agent" '
                        'param2="auto start" param3="disabled" param4="SIEMAgent"')
    assert "SIEM Agent Service Tampering" in titles
    reg = ('EventID=13 Channel="Microsoft-Windows-Sysmon/Operational" Computer="WIN01" EventType="SetValue" '
           'TargetObject="HKLM\\System\\CurrentControlSet\\Services\\SIEMAgent\\Start" Details="DWORD (0x00000004)" '
           'Image="{}"')
    assert "SIEM Agent Service Tampering" in _titles(
        engines, "windows_sysmon", reg.format("C:\\Windows\\regedit.exe"))[1]
    assert "SIEM Agent Service Tampering" not in _titles(
        engines, "windows_sysmon", reg.format("C:\\Windows\\System32\\services.exe"))[1]
