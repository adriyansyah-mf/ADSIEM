# tests/worker/test_linux_decoding.py
"""Linux auth / auditd / kernel, nginx error + ModSecurity and FortiGate event/UTM lines
through the shipped decoders and rules."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
H = "Oct 18 10:00:00 web01 "
H_ISO = "2026-10-18T10:00:00.123456+00:00 web01 "  # rsyslog's default on Debian 12+


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture()
def engines():
    import yaml
    decoders = sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decoders)
    sig = SigmaEngine()  # fresh per test: threshold windows are in-memory
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _run(engines, log_type, line):
    dec, sig = engines
    event, name = dec.decode_named(log_type, line)
    flat = {**event, "raw_message": line, "log_type": log_type, "hostname": "web01"}
    return event, name, [m["title"] for m in asyncio.run(sig.evaluate(flat))]


@pytest.mark.parametrize("log_type,line,decoder,action,fields", [
    ("linux_auth", H + "sshd[811]: Invalid user oracle from 45.1.2.3 port 5522",
     "ssh_invalid_user", "invalid_user", {"user.name": "oracle", "source.ip": "45.1.2.3"}),
    ("linux_auth", H_ISO + "sshd[811]: Invalid user oracle from 45.1.2.3 port 5522",
     "ssh_invalid_user", "invalid_user", {"source.ip": "45.1.2.3"}),
    ("linux_auth", H + "sshd[811]: Connection closed by invalid user test 45.1.2.3 port 5522 [preauth]",
     "ssh_preauth_disconnect", "preauth_disconnect", {"user.name": "test", "source.ip": "45.1.2.3"}),
    ("linux_auth", H + "sshd[811]: Connection closed by authenticating user root 45.1.2.3 port 5522 [preauth]",
     "ssh_preauth_disconnect", "preauth_disconnect", {"user.name": "root", "source.ip": "45.1.2.3"}),
    ("linux_auth", H + "sshd[811]: Failed publickey for root from 45.1.2.3 port 5522 ssh2: RSA SHA256:abc",
     "ssh_failed_publickey", "login_failed", {"user.name": "root", "source.ip": "45.1.2.3"}),
    ("linux_auth", H + "sshd[811]: error: maximum authentication attempts exceeded for root from 45.1.2.3 port 5522 ssh2 [preauth]",
     "ssh_max_auth_exceeded", "max_auth_exceeded", {"source.ip": "45.1.2.3"}),
    ("linux_auth", H + "sshd[811]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.1.2.3  user=root",
     "ssh_pam_auth_failure", "pam_auth_failure", {"source.ip": "45.1.2.3", "user.name": "root"}),
    ("linux_auth", H + "sshd[811]: Disconnected from user deploy 10.0.0.5 port 50000",
     "ssh_disconnected", "session_closed", {"user.name": "deploy"}),
    ("linux_auth", H + "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
     "linux_sudo_pam_failure", "sudo_auth_failure", {"user.name": "bob"}),
    ("linux_auth", H + "sudo:      bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "linux_sudo_incorrect_password", "sudo_failed", {"user.name": "bob", "user.target": "root"}),
    ("linux_auth", H + "sudo:      bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "linux_sudo_not_allowed", "sudo_denied", {"user.name": "bob", "process.command_line": "/bin/bash"}),
    ("linux_auth", H + "usermod[900]: add 'bob' to group 'sudo'",
     "linux_usermod_group_add", "user_added_to_group", {"user.target": "bob", "group.name": "sudo"}),
    ("linux_auth", H + "gpasswd[900]: user bob added by root to group docker",
     "linux_gpasswd_group_add", "user_added_to_group", {"user.target": "bob", "group.name": "docker"}),
    ("linux_auth", H + "userdel[900]: delete user 'bob'", "linux_userdel", "user_deleted", {"user.target": "bob"}),
    ("linux_auth", H + "passwd[900]: pam_unix(passwd:chauthtok): password changed for root",
     "linux_password_changed", "password_changed", {"user.target": "root"}),
    ("linux_auth", H + "groupadd[900]: new group: name=hackers, GID=1005",
     "linux_groupadd", "group_created", {"group.name": "hackers"}),
    ("linux_auth", H + "systemd-logind[500]: New session 42 of user root.",
     "linux_logind_session", "session_opened", {"user.name": "root"}),
    ("linux_auth", H + "polkitd[300]: Registered Authentication Agent for unix-process:1234",
     "linux_auth_generic", "auth_message", {"process.name": "polkitd", "host.hostname": "web01"}),
    ("linux_audit", 'type=USER_LOGIN msg=audit(1729245600.123:456): pid=811 uid=0 auid=4294967295 ses=4294967295 '
                    "msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=45.1.2.3 terminal=sshd res=failed'",
     "linux_audit_generic", "USER_LOGIN", {"user.name": "root", "source.ip": "45.1.2.3", "audit.result": "failed"}),
    ("linux_audit", 'type=PATH msg=audit(1729245600.1:8): item=0 name="/etc/shadow" inode=1 nametype=NORMAL',
     "linux_audit_generic", "PATH", {"file.path": "/etc/shadow"}),
    ("syslog", H + "kernel: [12345.678] Out of memory: Killed process 4242 (java) total-vm:4000000kB",
     "linux_kernel_oom_kill", "oom_kill", {"process.name": "java", "process.pid": "4242"}),
    ("syslog", H + "kernel: [12345.678] nginx[999]: segfault at 0 ip 00007f sp 00007ffe error 4 in libc.so.6[7f+1]",
     "linux_kernel_segfault", "segfault", {"process.name": "nginx"}),
    ("nginx_error", '2026/10/18 10:00:00 [error] 811#811: *1 access forbidden by rule, client: 45.1.2.3, '
                    'server: example.com, request: "GET /.env HTTP/1.1", host: "example.com"',
     "nginx_error", "web_error", {"source.ip": "45.1.2.3", "url.path": "/.env", "message": "access forbidden by rule"}),
    ("nginx_error", '2026/10/18 10:00:00 [error] 811#811: *1 [client 45.1.2.3] ModSecurity: Access denied with code 403 '
                    '(phase 2). Matched "Operator `Ge\' with parameter `5\'" [file "/etc/modsec/REQUEST-949.conf"] '
                    '[id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [severity "CRITICAL"] '
                    '[hostname "10.0.0.5"] [uri "/index.php"], client: 45.1.2.3, server: example.com, '
                    'request: "GET /index.php?id=1%27 HTTP/1.1", host: "example.com"',
     "nginx_modsecurity", "waf_match", {"event.outcome": "Access denied", "rule.id": "949110", "source.ip": "45.1.2.3",
                                        "http.response.status_code": "403", "waf.severity": "CRITICAL"}),
    ("fortigate_traffic", 'date=2026-10-18 time=10:00:00 devname="FG100" logid="0101039426" type="event" subtype="vpn" '
                          'level="alert" action="ssl-login-fail" user="admin" remip=45.1.2.3 reason="sslvpn_login_permission_denied"',
     "fortigate_vpn_login_failed", "login_failed", {"user.name": "admin", "source.ip": "45.1.2.3"}),
    ("fortigate_traffic", 'date=2026-10-18 time=10:00:00 devname="FG100" type="utm" subtype="ips" level="alert" '
                          'srcip=45.1.2.3 dstip=10.0.0.5 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" action="dropped"',
     "fortigate_utm", "utm_event", {"event.type": "ips", "rule.name": "Apache.Log4j.Error.Log.Remote.Code.Execution"}),
    ("fortigate_traffic", 'date=2026-10-18 time=10:00:00 devname="FG100" type="event" subtype="system" '
                          'logdesc="Admin login successful" user="admin" srcip=10.0.0.9 action="login" status="success"',
     "fortigate_event", "fortigate_event", {"event.type": "system"}),
])
def test_lines_decode(engines, log_type, line, decoder, action, fields):
    event, name, _ = _run(engines, log_type, line)
    assert name == decoder
    assert event["event.action"] == action
    for k, v in fields.items():
        assert event.get(k) == v, (k, event.get(k))


def test_existing_decoders_still_win(engines):
    _, name, _ = _run(engines, "linux_auth", H + "sshd[1]: Failed password for root from 45.1.2.3 port 22 ssh2")
    assert name == "linux_auth_failed"
    _, name, _ = _run(engines, "linux_auth", H + "sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 2 ssh2: RSA x")
    assert name == "ssh_accepted"
    _, name, _ = _run(engines, "fortigate_traffic", 'date=2026-10-18 type="traffic" subtype="forward" srcip=1.2.3.4 action="deny"')
    assert name == "fortigate_traffic"


def test_sudo_typo_is_not_a_failed_su(engines):
    line = H + "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob"
    _, _, titles = _run(engines, "linux_auth", line)
    assert "Failed su Authentication" not in titles
    # su itself still is
    su = H + "su: pam_unix(su-l:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root"
    _, name, titles = _run(engines, "linux_auth", su)
    assert name == "linux_su_pam_failure" and "Failed su Authentication" in titles


def test_username_enumeration_correlation(engines):
    titles = []
    for user in ["admin", "oracle", "test", "ubuntu", "postgres"]:
        titles += _run(engines, "linux_auth", H + f"sshd[811]: Invalid user {user} from 45.1.2.3 port 5522")[2]
    # the base rule is silenced; only the correlation alerts, once the 5th distinct name arrives
    assert [t for t in titles if t.startswith("SSH Username Enumeration")] == [
        "SSH Username Enumeration [5 distinct user.name in 600s for 45.1.2.3]"]


def test_preauth_brute_force_threshold(engines):
    titles = []
    for i in range(15):
        titles += _run(engines, "linux_auth",
                       H + f"sshd[{i}]: Connection closed by authenticating user root 45.1.2.3 port {5000 + i} [preauth]")[2]
    assert any(t.startswith("SSH Brute Force (pre-authentication)") for t in titles)


@pytest.mark.parametrize("line,title,fires", [
    (H + "sudo:      bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "Sudo Command Denied by Sudoers", True),
    (H + "usermod[900]: add 'bob' to group 'sudo'", "User Added to Privileged Linux Group", True),
    (H + "usermod[900]: add 'bob' to group 'audio'", "User Added to Privileged Linux Group", False),
    (H + "passwd[900]: pam_unix(passwd:chauthtok): password changed for root", "Root Password Changed", True),
    (H + "passwd[900]: pam_unix(passwd:chauthtok): password changed for bob", "Root Password Changed", False),
    (H + "userdel[900]: delete user 'bob'", "Local User Account Deleted", True),
])
def test_account_rules(engines, line, title, fires):
    assert (title in _run(engines, "linux_auth", line)[2]) is fires


def test_fortigate_rules(engines):
    ips = ('date=2026-10-18 devname="FG100" type="utm" subtype="ips" srcip=45.1.2.3 dstip=10.0.0.5 '
           'attack="Apache.Log4j.Error.Log.Remote.Code.Execution" action="dropped"')
    assert "FortiGate IPS Detected an Attack" in _run(engines, "fortigate_traffic", ips)[2]
    vpn = 'date=2026-10-18 devname="FG100" type="event" subtype="vpn" action="ssl-login-fail" user="admin" remip=45.1.2.3'
    titles = []
    for _ in range(10):
        titles += _run(engines, "fortigate_traffic", vpn)[2]
    assert any(t.startswith("FortiGate VPN / Admin Login Brute Force") for t in titles)
    # FortiGate login failures don't feed the Linux SSH rules (different logsource)
    assert not any(t.startswith("SSH") for t in titles)


def test_waf_repeated_blocks(engines):
    line = ('2026/10/18 10:00:00 [error] 1#1: *1 [client 45.1.2.3] ModSecurity: Access denied with code 403 (phase 2). '
            '[id "942100"] [msg "SQL Injection Attack Detected via libinjection"], client: 45.1.2.3, server: x, '
            'request: "GET /?q=1 HTTP/1.1"')
    titles = []
    for _ in range(20):
        titles += _run(engines, "nginx_error", line)[2]
    assert any(t.startswith("WAF Blocking Repeated Attacks") for t in titles)
