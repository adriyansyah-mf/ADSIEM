# tests/worker/test_decoder_engine.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../worker'))
import pytest
from worker.decoder_engine import DecoderEngine

DECODER_YAML_AUTH = """
name: linux_auth_failed
log_type: linux_auth
type: regex
priority: 10
enabled: true
pattern: 'Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+) port (?P<port>\\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip
  user.name: user
  source.port: port
"""

DECODER_YAML_SUDO = """
name: linux_sudo
log_type: linux_auth
type: regex
priority: 20
enabled: true
pattern: '(?P<user>\\S+) : TTY=(?P<tty>\\S+) ; PWD=(?P<pwd>\\S+) ; USER=(?P<run_as>\\S+) ; COMMAND=(?P<cmd>.+)'
fields:
  event.category: process
  event.action: sudo_command
  user.name: user
  process.command_line: cmd
"""

def test_decode_ssh_failed_password():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.action"] == "login_failed"
    assert result["source.ip"] == "1.2.3.4"
    assert result["user.name"] == "root"

def test_no_match_returns_empty():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "Accepted publickey for admin from 10.0.0.1 port 22"
    result = engine.decode("linux_auth", raw)
    assert result == {}

def test_wrong_log_type_skipped():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("nginx_access", raw)
    assert result == {}

def test_priority_order_first_match_wins():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_SUDO, DECODER_YAML_AUTH])
    raw = "May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.action"] == "login_failed"

def test_static_field_applied():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "May 21 sshd: Failed password for alice from 10.0.0.1 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.category"] == "authentication"
