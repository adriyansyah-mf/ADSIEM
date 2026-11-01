# tests/worker/test_windows_etw_file.py
"""The agent's ETW file and image lines (agent/internal/winsensor/file.go)
decode like Sysmon 11/23/7/6 and reach windows/file_event, file_delete,
image_load and driver_load rules, and only those."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# As TestFileCreateRenameDelete / TestImageAndDriverLoads format them.
CREATE = ('EventID=11 Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="7" '
          'Image="C:\\Tools\\locker.exe" FileAction="create" TargetFilename="C:\\Users\\alice\\Desktop\\READ_ME.txt"')
RENAME = ('EventID=11 Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="7" '
          'Image="C:\\Tools\\locker.exe" FileAction="rename" TargetFilename="C:\\Users\\alice\\doc.txt.locked" '
          'SourceFilename="C:\\Users\\alice\\doc.txt"')
DELETE = ('EventID=23 Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="7" '
          'Image="C:\\Tools\\locker.exe" FileAction="delete" TargetFilename="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"')
IMAGE = ('EventID=7 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="6796" '
         'Image="C:\\Program Files\\Microsoft Office\\WINWORD.EXE" ImageLoaded="C:\\Windows\\System32\\clr.dll"')
DRIVER = ('EventID=6 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" '
          'ImageLoaded="C:\\Users\\alice\\AppData\\Local\\Temp\\rootkit.sys"')
SUMMARY = ('EventID=1100 Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="7" '
           'Image="C:\\Tools\\locker.exe" FileAction="summary" Creates="0" Renames="400" Deletes="0" '
           'TargetFilename="C:\\Users\\alice\\x.locked"')


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.mark.parametrize("log_type,line,decoder,fields", [
    ("windows_etw_file", CREATE, "win_etw_file_event",
     {"TargetFilename": "C:\\Users\\alice\\Desktop\\READ_ME.txt", "process.executable": "C:\\Tools\\locker.exe",
      "event.category": "file", "event.action": "file_created"}),
    ("windows_etw_file", RENAME, "win_etw_file_event",
     {"SourceFilename": "C:\\Users\\alice\\doc.txt", "FileAction": "rename", "file.path": "C:\\Users\\alice\\doc.txt.locked"}),
    ("windows_etw_file", DELETE, "win_etw_file_delete", {"event.action": "file_deleted", "process.pid": "7"}),
    ("windows_etw_image", IMAGE, "win_etw_image_load",
     {"ImageLoaded": "C:\\Windows\\System32\\clr.dll", "dll.path": "C:\\Windows\\System32\\clr.dll",
      "event.action": "image_loaded"}),
    ("windows_etw_image", DRIVER, "win_etw_driver_load",
     {"ImageLoaded": "C:\\Users\\alice\\AppData\\Local\\Temp\\rootkit.sys", "event.action": "driver_loaded"}),
])
def test_file_and_image_lines_decode(decoders, log_type, line, decoder, fields):
    event, name = decoders.decode_named(log_type, line)
    assert name == decoder
    for key, value in fields.items():
        assert event.get(key) == value, (key, event.get(key))


RULES = {
    "file_event": """
title: Locked Extension
logsource: {product: windows, category: file_event}
detection:
  selection:
    TargetFilename|endswith: '.locked'
  condition: selection
""",
    "ransom_note": """
title: Ransom Note
logsource: {product: windows, category: file_event}
detection:
  selection:
    TargetFilename|endswith: '\\\\READ_ME.txt'
  condition: selection
""",
    "file_delete": """
title: Event Log Deleted
logsource: {product: windows, category: file_delete}
detection:
  selection:
    TargetFilename|endswith: '.evtx'
  condition: selection
""",
    "image_load": """
title: CLR In Office
logsource: {product: windows, category: image_load}
detection:
  selection:
    Image|endswith: '\\\\WINWORD.EXE'
    ImageLoaded|endswith: '\\\\clr.dll'
  condition: selection
""",
    "driver_load": """
title: Driver From Temp
logsource: {product: windows, category: driver_load}
detection:
  selection:
    ImageLoaded|contains: '\\\\Temp\\\\'
  condition: selection
""",
}


def test_each_line_reaches_only_its_category():
    eng = SigmaEngine()
    eng.load_from_yaml_list(list(RULES.values()))
    assert not eng.load_errors, eng.load_errors

    def titles(log_type, line):
        return sorted(m["title"] for m in asyncio.run(eng.evaluate({"log_type": log_type, "raw_message": line})))

    assert titles("windows_etw_file", CREATE) == ["Ransom Note"]
    assert titles("windows_etw_file", RENAME) == ["Locked Extension"]
    assert titles("windows_etw_file", DELETE) == ["Event Log Deleted"]
    assert titles("windows_etw_image", IMAGE) == ["CLR In Office"]
    assert titles("windows_etw_image", DRIVER) == ["Driver From Temp"]
    # a summary is searchable but reaches no category
    assert titles("windows_etw_file", SUMMARY) == []


def test_shipped_rules_load():
    eng = SigmaEngine()
    eng.load_from_yaml_list(_load("rules/*.yaml"))
    assert not eng.load_errors, eng.load_errors
