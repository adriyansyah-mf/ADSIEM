# worker/worker/agent_self.py
"""The agent's own App Control runs: the agent starts the PowerShell script it
wrote under its state folder (appcontrol\\scripts\\run.ps1, agent
internal/appcontrol ScriptFileRunner) as a child of siem-agent.exe. That is
the agent's activity on the host, not an attack, so the rules raise no alert
for it (a case about the agent's own run was the reason for this)."""
from __future__ import annotations

import re

AGENT_IMAGES = ("siem-agent.exe", "siem-agent")
SCRIPT_DIR = "\\appcontrol\\scripts\\"


def _base(p: str) -> str:
    return re.split(r"[\\/]", p)[-1].lower()


def is_agent_script_run(event: dict) -> bool:
    """True when the event is a process the agent started to run its own
    App Control script (parent siem-agent, command line runs a .ps1 from the
    agent's appcontrol\\scripts folder)."""
    parent = str(event.get("ParentImage") or event.get("process.parent.name") or "")
    if _base(parent) not in AGENT_IMAGES:
        return False
    cmd = str(event.get("CommandLine") or event.get("process.command_line") or "").lower().replace("/", "\\")
    return SCRIPT_DIR in cmd and ".ps1" in cmd
