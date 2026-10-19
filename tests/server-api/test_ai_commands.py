# tests/server-api/test_ai_commands.py
"""AI-requested commands: what may skip approval, and exec staying out of artifacts."""
import pytest

from app.services.flow_artifacts import ArtifactError, build_row_filter, column_order, parse_artifact
from app.services.investigator import auto_approvable, command_line

ALLOW = frozenset({"whoami", "hostname", "ipconfig", "cat", "powershell", "bash"})

EXEC_ARTIFACT = """name: Custom.RunAnything
sources:
  - name: Out
    plugin: exec
    args:
      command: /bin/sh
"""


def test_only_listed_programs_skip_approval():
    assert auto_approvable("whoami", [], ALLOW)
    assert auto_approvable("/usr/bin/hostname", ["-f"], ALLOW)
    assert auto_approvable(r"C:\Windows\System32\IPCONFIG.EXE", ["/all"], ALLOW)
    assert not auto_approvable("ss", ["-tnp"], ALLOW)
    assert not auto_approvable("whoami", [], frozenset())


def test_shells_and_interpreters_always_need_a_human():
    assert not auto_approvable("powershell", ["-Command", "Get-Process"], ALLOW)
    assert not auto_approvable("/bin/bash", ["-c", "id"], ALLOW)


def test_credential_stores_always_need_a_human():
    assert not auto_approvable("cat", ["/etc/shadow"], ALLOW)
    assert not auto_approvable("cat", ["/root/.ssh/id_ed25519"], ALLOW)
    assert auto_approvable("cat", ["/etc/hostname"], ALLOW)


def test_command_line_quotes_what_a_shell_would_split():
    assert command_line("ss", ["-tnp"]) == "ss -tnp"
    assert command_line("powershell", ["-Command", "Get-Process | Sort CPU"]) == \
        'powershell -Command "Get-Process | Sort CPU"'


def test_exec_is_refused_in_saved_artifacts():
    with pytest.raises(ArtifactError, match="unknown plugin 'exec'"):
        parse_artifact(EXEC_ARTIFACT)


def test_command_flow_snapshots_still_filter_and_order():
    from app.api.routes.flows import _COMMAND_CONTENT

    rows = [{"Text": "hi", "Stream": "stdout", "Line": 1}, {"Stream": "exit", "Line": 0, "Text": "exit code 0",
                                                           "ExitCode": 0}]
    assert build_row_filter(_COMMAND_CONTENT, {"command": "echo", "args": ["hi"]}).apply("Output", rows) == rows
    assert column_order(_COMMAND_CONTENT, "Output", rows) == ["Stream", "Line", "Text", "ExitCode"]
