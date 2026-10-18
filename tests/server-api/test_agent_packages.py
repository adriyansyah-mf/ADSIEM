# tests/server-api/test_agent_packages.py
"""Package file names written by agent/packaging/* → what the deploy wizard lists."""
import pytest

from app.api.routes.agents import _parse_package


@pytest.mark.parametrize("name,expected", [
    ("siem-agent_1.5.1_amd64.deb", {"type": "deb", "version": "1.5.1", "arch": "amd64"}),
    ("siem-agent_1.5.1_arm64.deb", {"type": "deb", "version": "1.5.1", "arch": "arm64"}),
    ("siem-agent-1.5.1-1.x86_64.rpm", {"type": "rpm", "version": "1.5.1", "arch": "x86_64"}),
    ("siem-agent-windows-amd64-1.5.1.zip", {"type": "windows", "version": "1.5.1", "arch": "amd64"}),
    ("siem-agent-1.5.1-x64.msi", {"type": "msi", "version": "1.5.1", "arch": "x64"}),
])
def test_known_package_names(name, expected):
    assert _parse_package(name) == expected


@pytest.mark.parametrize("name", ["notes.txt", "evil.msi", "siem-agent-latest-x64.msi", "siem-agent.zip"])
def test_other_files_are_not_served(name):
    assert _parse_package(name) is None
