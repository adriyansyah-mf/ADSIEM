# tests/worker/test_agent_self.py
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.agent_self import is_agent_script_run  # noqa: E402

RUN = r"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\SIEMAgent\appcontrol\scripts\run.ps1"


def test_agent_script_run_is_recognised():
    assert is_agent_script_run({"ParentImage": r"C:\Program Files\SIEMAgent\siem-agent.exe", "CommandLine": RUN})


def test_process_name_only_parent_is_recognised():
    assert is_agent_script_run({"process.parent.name": "siem-agent.exe", "process.command_line": RUN})


def test_other_parent_is_not_recognised():
    assert not is_agent_script_run({"ParentImage": r"C:\Windows\explorer.exe", "CommandLine": RUN})


def test_encoded_command_from_agent_is_not_recognised():
    # an encoded command has no script path in its command line
    line = "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"
    assert not is_agent_script_run({"ParentImage": "siem-agent.exe", "CommandLine": line})


def test_script_outside_agent_folder_is_not_recognised():
    line = r"powershell.exe -File C:\Users\x\evil.ps1"
    assert not is_agent_script_run({"ParentImage": "siem-agent.exe", "CommandLine": line})
