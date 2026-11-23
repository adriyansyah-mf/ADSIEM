"""Webshell detection on the agent's eBPF process-exec lines.

The lines are the ones otakunesia sent on 14 Nov 2026, when a PHP webshell
under apache2 ran recon. The apache2 workers started before the agent, so
those lines carry no ParentImage, only Comm="apache2" and User=33: the
detection has to work from those, and from ParentImage once agents fill it."""
import asyncio
import glob
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

SHELL_FROM_APACHE = ('Image="/bin/sh" CommandLine="sh -c -- cat /etc/mysql/debian.cnf 2>&1 | head -8" '
                     'PID=3407896 PPID=3407532 User=33 Comm="apache2"')
SHELL_FROM_APACHE_WITH_PARENT = SHELL_FROM_APACHE + ' ParentImage="/usr/sbin/apache2"'
SHELL_FROM_PHP_FPM = ('Image="/usr/bin/dash" CommandLine="sh -c id" PID=11 PPID=10 User=33 '
                      'Comm="php-fpm8.1" ParentImage="/usr/sbin/php-fpm8.1"')
RECON_UNDER_SHELL = ('Image="/usr/bin/find" CommandLine="find / -xdev -type f -perm -o+w -newer" '
                     'PID=3407901 PPID=3407896 User=33 ParentImage="/bin/sh" Comm="sh"')
WHOAMI_UNDER_SHELL = ('Image="/usr/bin/whoami" CommandLine="whoami" PID=12 PPID=11 User=33 '
                      'ParentImage="/bin/sh" Comm="sh"')
# the app's own shell-outs that a web server user makes
GIT_UNDER_SHELL = ('Image="/usr/bin/git" CommandLine="git -c safe.directory=* log -1" PID=3407890 '
                   'PPID=3407889 User=33 ParentImage="/bin/sh" Comm="sh"')
ADMIN_SHELL = ('Image="/bin/bash" CommandLine="bash" PID=5 PPID=4 User=0 '
               'ParentImage="/usr/sbin/sshd" Comm="sshd"')
ADMIN_WHOAMI = ('Image="/usr/bin/whoami" CommandLine="whoami" PID=6 PPID=5 User=1000 '
                'ParentImage="/bin/bash" Comm="bash"')

SPAWN = "Web Server Started A Shell"
RECON = "Web Server User Ran Discovery Or Download Tool"


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def _alerts(decoders, rules, line):
    event, _ = decoders.decode_named("linux_process_exec", line)
    view = dict(event, raw_message=line, log_type="linux_process_exec", hostname="web-01")
    return {m["title"]: m["level"] for m in asyncio.run(rules.evaluate(view))}


@pytest.mark.parametrize("line", [SHELL_FROM_APACHE, SHELL_FROM_APACHE_WITH_PARENT, SHELL_FROM_PHP_FPM])
def test_web_server_starting_a_shell_alerts(decoders, rules, line):
    assert _alerts(decoders, rules, line).get(SPAWN) == "critical"


@pytest.mark.parametrize("line", [RECON_UNDER_SHELL, WHOAMI_UNDER_SHELL])
def test_web_server_user_recon_alerts(decoders, rules, line):
    assert _alerts(decoders, rules, line).get(RECON) == "high"


@pytest.mark.parametrize("line", [GIT_UNDER_SHELL, ADMIN_SHELL, ADMIN_WHOAMI])
def test_ordinary_execs_stay_quiet(decoders, rules, line):
    got = _alerts(decoders, rules, line)
    assert SPAWN not in got and RECON not in got, got
