# tests/worker/test_windows_rules.py
"""The Windows rules on file, image, driver and process telemetry fire on the
agent's ETW lines (agent/internal/winsensor) and on Sysmon's, and stay quiet
on the look-alike benign activity each rule leaves out."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def q(v):  # winevent.Quote: backslashes are not escaped
    return '"' + v + '"'


def file_line(event_id, image, target, action="create"):
    return (f'EventID={event_id} Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="4321" '
            f'Image={q(image)} User="WIN01\\alice" FileAction="{action}" TargetFilename={q(target)}')


def image_line(image, loaded):
    return (f'EventID=7 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="4321" '
            f'Image={q(image)} User="WIN01\\alice" ImageLoaded={q(loaded)}')


def driver_line(loaded):
    return f'EventID=6 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ImageLoaded={q(loaded)}'


def proc_line(image, cmd):
    return (f'EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="4321" '
            f'Image={q(image)} CommandLine={q(cmd)} User="WIN01\\alice" IntegrityLevel="High" '
            f'ParentProcessId="1000" ParentImage="C:\\Windows\\System32\\cmd.exe"')


USERS = "C:\\Users\\alice"
SYS = "C:\\Windows\\System32"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16"

CASES = [
    # (log_type, line, title or None for "no new Windows rule fires")
    ("windows_etw_file", file_line(11, f"{USERS}\\AppData\\Local\\Temp\\x.exe", f"{USERS}\\Documents\\_readme.txt"),
     "Ransom Note Dropped"),
    ("windows_etw_file", file_line(11, f"{USERS}\\x.exe", f"{USERS}\\Desktop\\HOW_TO_DECRYPT_FILES.html"),
     "Ransom Note Dropped"),
    ("windows_etw_file", file_line(11, f"{SYS}\\notepad.exe", f"{USERS}\\Documents\\readme.txt"), None),
    ("windows_etw_file", file_line(11, f"{USERS}\\a.exe",
                                   f"{USERS}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.vbs"),
     "Executable Or Script Dropped In Startup Folder"),
    ("windows_etw_file", file_line(11, "C:\\Program Files\\Zoom\\Zoom.exe",
                                   f"{USERS}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Zoom.lnk"),
     None),
    ("windows_etw_file", file_line(11, f"{OFFICE}\\WINWORD.EXE", f"{USERS}\\AppData\\Local\\Temp\\stage.exe"),
     "Office Application Drops Executable Or Script"),
    ("windows_etw_file", file_line(11, f"{OFFICE}\\WINWORD.EXE", f"{USERS}\\Documents\\report.docx"), None),
    ("windows_etw_file", file_line(11, f"{SYS}\\rundll32.exe", "C:\\Windows\\Temp\\lsass.dmp"),
     "LSASS Memory Dump File Created"),
    ("windows_etw_file", file_line(23, f"{USERS}\\x.exe", f"{SYS}\\winevt\\Logs\\Security.evtx", "delete"),
     "Windows Event Log File Deleted"),
    ("windows_etw_file", file_line(23, f"{USERS}\\x.exe", f"{USERS}\\Desktop\\old.evtx", "delete"), None),
    ("windows_etw_image", image_line(f"{SYS}\\dllhost.exe", f"{USERS}\\Downloads\\version.dll"),
     "System Binary Loads DLL From User-Writable Folder"),
    ("windows_etw_image", image_line(f"{SYS}\\svchost.exe",
                                     "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpOav.dll"), None),
    ("windows_etw_image", image_line(f"{OFFICE}\\EXCEL.EXE", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll"),
     ".NET Runtime Loaded Into Office Application"),
    ("windows_etw_image", driver_line(f"{USERS}\\AppData\\Local\\Temp\\evil.sys"),
     "Kernel Driver Loaded From User-Writable Folder"),
    ("windows_etw_image", driver_line(f"{SYS}\\drivers\\RTCore64.sys"), "Known Vulnerable Driver Loaded"),
    ("windows_etw_image", driver_line(f"{SYS}\\drivers\\tcpip.sys"), None),
    ("windows_etw_process", proc_line(f"{SYS}\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
     "Shadow Copies Or Backups Deleted"),
    ("windows_etw_process", proc_line(f"{SYS}\\wbem\\WMIC.exe", "wmic shadowcopy delete"),
     "Shadow Copies Or Backups Deleted"),
    ("windows_etw_process", proc_line(f"{SYS}\\bcdedit.exe", "bcdedit /set {default} recoveryenabled No"),
     "Shadow Copies Or Backups Deleted"),
    ("windows_etw_process", proc_line(f"{SYS}\\vssadmin.exe", "vssadmin list shadows"), None),
    ("windows_etw_process", proc_line(f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true"),
     "Defender Protection Disabled Via PowerShell"),
    ("windows_etw_process", proc_line(f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "powershell -c Set-MpPreference -SignatureUpdateInterval 4"), None),
    ("windows_etw_process", proc_line(f"{SYS}\\wevtutil.exe", "wevtutil.exe cl Security"),
     "Event Log Cleared With Wevtutil"),
    ("windows_etw_process", proc_line(f"{SYS}\\wevtutil.exe", "wevtutil.exe qe Security /c:5"), None),
]

NEW = {"Ransom Note Dropped", "Executable Or Script Dropped In Startup Folder",
       "Office Application Drops Executable Or Script", "LSASS Memory Dump File Created",
       "Windows Event Log File Deleted", "System Binary Loads DLL From User-Writable Folder",
       ".NET Runtime Loaded Into Office Application", "Kernel Driver Loaded From User-Writable Folder",
       "Known Vulnerable Driver Loaded", "Shadow Copies Or Backups Deleted",
       "Defender Protection Disabled Via PowerShell", "Event Log Cleared With Wevtutil"}


def _new_titles(decoders, rules, log_type, line):
    event, _ = decoders.decode_named(log_type, line)
    view = dict(event, raw_message=line, log_type=log_type, hostname="win01")
    return {m["title"] for m in asyncio.run(rules.evaluate(view))} & NEW


@pytest.mark.parametrize("log_type,line,title", CASES)
def test_etw_lines(decoders, rules, log_type, line, title):
    assert _new_titles(decoders, rules, log_type, line) == ({title} if title else set())


SYSMON_TYPE = {"windows_etw_file": "windows_sysmon", "windows_etw_image": "windows_sysmon",
               "windows_etw_process": "windows_sysmon"}


@pytest.mark.parametrize("log_type,line,title", CASES)
def test_same_lines_from_sysmon(decoders, rules, log_type, line, title):
    # Sysmon's lines carry its channel; the rules use categories, not log types
    sysmon = line.replace('Channel="ETW"', 'Channel="Microsoft-Windows-Sysmon/Operational"')
    assert _new_titles(decoders, rules, SYSMON_TYPE[log_type], sysmon) == ({title} if title else set())


def test_every_new_rule_has_a_positive_case():
    assert {t for _, _, t in CASES if t} == NEW
