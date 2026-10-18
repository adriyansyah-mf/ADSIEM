# tests/worker/test_sigma_logsource.py
"""Logsource routing, SigmaHQ field conventions and the engine features SigmaHQ rules rely on."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import _parse_kv
from worker.sigma_engine import SigmaEngine
from worker.sigma_logsource import is_collected

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _engine(*rules, **kw):
    eng = SigmaEngine(**kw)
    eng.load_from_yaml_list(list(rules))
    assert not eng.load_errors, eng.load_errors
    return eng


def _titles(eng, event):
    return [m["title"] for m in asyncio.run(eng.evaluate(event))]


WIN_PROC = """
title: Whoami
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
"""
LINUX_ANY = """
title: Linux Failed
logsource: {product: linux}
detection:
  selection:
    event.action: login_failed
  condition: selection
"""
WIN_SEC_FAILED = """
title: Windows Failed
logsource: {product: windows, service: security}
detection:
  selection:
    event.action: login_failed
  condition: selection
"""
NO_LOGSOURCE = """
title: Anywhere
detection:
  selection:
    event.action: login_failed
  condition: selection
"""


def test_rules_only_see_events_from_their_logsource():
    eng = _engine(WIN_SEC_FAILED, LINUX_ANY, NO_LOGSOURCE)
    ssh = {"log_type": "linux_auth", "event.action": "login_failed", "raw_message": "sshd[1]: Failed password"}
    win = {"log_type": "windows_security", "event.action": "login_failed",
           "raw_message": 'EventID=4625 Channel="Security"'}
    assert sorted(_titles(eng, ssh)) == ["Anywhere", "Linux Failed"]
    assert sorted(_titles(eng, win)) == ["Anywhere", "Windows Failed"]
    # no log_type (rule tests, artifact rows): every rule applies, as before
    assert len(_titles(eng, {"event.action": "login_failed"})) == 3


@pytest.mark.parametrize("line,hit", [
    (f'EventID=1 Channel="{SYSMON}" Image="C:\\Windows\\System32\\whoami.exe"', True),
    # same image, but Sysmon 3 is network_connection, not process_creation
    (f'EventID=3 Channel="{SYSMON}" Image="C:\\Windows\\System32\\whoami.exe"', False),
    # Security 4688 is process creation too (its decoder maps NewProcessName → Image)
    ('EventID=4688 Channel="Security" Image="C:\\Windows\\System32\\whoami.exe"', True),
])
def test_windows_categories_follow_channel_and_event_id(line, hit):
    eng = _engine(WIN_PROC)
    log_type = "windows_security" if "Security" in line else "windows_sysmon"
    assert (_titles(eng, {"log_type": log_type, "raw_message": line}) == ["Whoami"]) is hit


def test_any_channel_maps_to_its_sigma_service():
    defender = """
title: Defender Exclusion
logsource: {product: windows, service: windefend}
detection:
  selection:
    EventID: 5007
    NewValue|contains: '\\Microsoft\\Windows Defender\\Exclusions'
  condition: selection
"""
    eng = _engine(defender)
    line = ('EventID=5007 Channel="Microsoft-Windows-Windows Defender/Operational" '
            'Provider="Microsoft-Windows-Windows Defender" NewValue="HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\x = 0x0"')
    # an extra channel with no decoder: the raw key=value pairs are the fields
    assert _titles(eng, {"log_type": "windows_eventlog", "raw_message": line}) == ["Defender Exclusion"]
    assert _titles(eng, {"log_type": "windows_eventlog", "raw_message": line.replace("Defender/Operational", "X")}) == []


def test_provider_name_alias_and_quoted_command_lines():
    rule = """
title: Browser Download
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Provider_Name: Microsoft-Windows-Sysmon
    CommandLine|contains: '.zip"'
  condition: selection
"""
    eng = _engine(rule)
    line = (f'EventID=1 Channel="{SYSMON}" Provider="Microsoft-Windows-Sysmon" '
            'CommandLine="\\"C:\\Program Files\\Edge\\msedge.exe\\" \\"http://10.0.0.1/a.zip\\""')
    assert _titles(eng, {"log_type": "windows_sysmon", "raw_message": line}) == ["Browser Download"]


def test_kv_unescaping_matches_the_agent_encoding():
    kv = _parse_kv('A="say \\"hi\\"" B="C:\\Windows\\System32" C="C:\\Temp\\\\" D="\\\\\\server\\share" E=plain')
    assert kv == {"A": 'say "hi"', "B": "C:\\Windows\\System32", "C": "C:\\Temp\\",
                  "D": "\\\\server\\share", "E": "plain"}


def test_webserver_category_gets_iis_style_fields():
    rule = """
title: SQLi
logsource: {category: webserver}
detection:
  selection:
    cs-method: GET
    cs-uri-query|contains: union select
  filter:
    cs-uri-stem|endswith: .css
  condition: selection and not filter
"""
    eng = _engine(rule)
    ev = {"log_type": "nginx_access_combined", "http.request.method": "GET",
          "url.path": "/item.php?id=1 union select 1", "raw_message": "x"}
    assert _titles(eng, ev) == ["SQLi"]
    assert _titles(eng, {**ev, "url.path": "/style.css?q=union select"}) == []
    assert _titles(eng, {**ev, "log_type": "linux_auth"}) == []


def test_fieldref_with_match_modifiers():
    rule = """
title: Same User
detection:
  selection:
    TargetUserName|fieldref|startswith: SubjectUserName
  condition: selection
"""
    eng = _engine(rule)
    assert _titles(eng, {"TargetUserName": "Admin-backup", "SubjectUserName": "admin"}) == ["Same User"]
    assert _titles(eng, {"TargetUserName": "bob", "SubjectUserName": "admin"}) == []


def test_expand_placeholders():
    rule = """
title: Not From Jump Host
detection:
  selection:
    event.action: login_success
  filter:
    source.ip|expand: '%jump_hosts%'
  condition: selection and not filter
"""
    eng = _engine(rule, placeholders={"jump_hosts": ["10.0.0.5", "10.0.0.6"]})
    assert _titles(eng, {"event.action": "login_success", "source.ip": "10.0.0.9"}) == ["Not From Jump Host"]
    assert _titles(eng, {"event.action": "login_success", "source.ip": "10.0.0.5"}) == []
    # unconfigured placeholder: the filter matches nothing, the rule still runs
    eng = _engine(rule, placeholders={})
    assert _titles(eng, {"event.action": "login_success", "source.ip": "10.0.0.5"}) == ["Not From Jump Host"]


def test_suppression_is_per_host_without_a_source_ip():
    rule = """
title: Proc Rule
detection:
  selection:
    Image|endswith: evil.exe
  condition: selection
suppression:
  timewindow: 600
"""
    eng = _engine(rule)
    ev = {"Image": "C:\\evil.exe", "hostname": "pc1"}
    assert _titles(eng, ev) == ["Proc Rule"]
    assert _titles(eng, ev) == []                            # suppressed on pc1
    assert _titles(eng, {**ev, "hostname": "pc2"}) == ["Proc Rule"]  # but not fleet-wide


def test_value_lists_and_keywords_keep_sigma_semantics():
    rule = """
title: Lists
detection:
  sel_img:
    Image|endswith: ['\\a.exe', '\\b.exe']
  sel_cmd:
    CommandLine|contains: ['-enc ', 'downloadstring', 'iex*http']
  keywords:
    - 'mimikatz'
    - 'sekurlsa::*'
  condition: (sel_img and sel_cmd) or keywords
"""
    eng = _engine(rule)
    assert _titles(eng, {"Image": "C:\\x\\B.EXE", "CommandLine": "x IEX (iwr http://e)"}) == ["Lists"]
    assert _titles(eng, {"Image": "C:\\x\\c.exe", "CommandLine": "-enc AAA"}) == []
    assert _titles(eng, {"raw_message": "run SEKURLSA::logonpasswords"}) == ["Lists"]
    assert _titles(eng, {"raw_message": "nothing to see"}) == []


def test_is_collected():
    assert is_collected({"product": "windows", "category": "process_creation"}, {"windows_sysmon"})
    assert is_collected({"product": "linux", "service": "sshd"}, {"linux_auth"})
    assert not is_collected({"product": "macos", "category": "process_creation"}, {"windows_sysmon", "linux_auth"})
    assert not is_collected({"product": "aws", "service": "cloudtrail"}, {"windows_sysmon"})
    assert is_collected({"product": "fortigate", "service": "traffic"}, {"fortigate_traffic"})  # derived
    assert is_collected({}, set())


def test_reload_reuses_compiled_rules():
    contents = [WIN_PROC, LINUX_ANY]
    first = _engine(*contents)
    second = _engine(*contents)
    # same compiled matcher objects: the periodic reload doesn't recompile unchanged rules
    assert first.rules[0].matcher is second.rules[0].matcher
