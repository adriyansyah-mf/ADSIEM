# tests/worker/test_linux_sensor.py
"""Lines from the agent's eBPF sensor (agent/internal/linsensor) decode and
reach the shipped rules, and SigmaHQ linux file_event / file_delete rules
see them through the Sigma-native TargetFilename / Image fields."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")

# Formats as TestSensorEndToEnd (a real kernel) and processor_test.go produce them.
FILE_CREATE = ('action=create TargetFilename="/etc/ld.so.preload" Image="/usr/bin/tee" Comm="tee" '
               'PID=4242 PPID=4200 User=0')
FILE_KEYS = ('action=rename TargetFilename="/root/.ssh/authorized_keys" SourceFilename="/root/.ssh/k.tmp" '
             'Image="/usr/bin/mv" Comm="mv" PID=4243 PPID=4200 User=0')
FILE_DELETE = ('action=delete TargetFilename="/var/log/auth.log" Image="/usr/bin/shred" Comm="shred" '
               'PID=4244 PPID=4200 User=0')
FILELESS = ('Image="/memfd:e2e-payload" ExecPath="/proc/self/fd/4" Links=0 Comm="4" PID=1949604 '
            'PPID=1949587 User=0 EUID=0 ParentImage="/tmp/.x/loader"')
PTRACE_ATTACH = ('action=attach TargetPID=812 TargetImage="/usr/sbin/sshd" Image="/tmp/.x/inject" '
                 'Comm="inject" PID=5001 PPID=1 User=0 EUID=0')
PTRACE_GDB = ('action=attach TargetPID=812 TargetImage="/usr/bin/app" Image="/usr/bin/gdb" '
              'Comm="gdb" PID=5002 PPID=1 User=1000 EUID=1000')
PTRACE_POKE_GDB = ('action=pokedata TargetPID=812 TargetImage="/usr/bin/app" Image="/usr/bin/gdb" '
                   'Comm="gdb" PID=5002 PPID=1 User=1000 EUID=1000')
SETUID_EXPLOIT = ('action=setuid IDs="0" Image="/tmp/cve-2026-x" Comm="cve-2026-x" PID=6001 PPID=6000 '
                  'User=1000 EUID=1000 ParentImage="/usr/bin/bash"')
SETUID_SUDO = ('action=setresuid IDs="0,0,0" Image="/usr/bin/sudo" Comm="sudo" PID=6002 PPID=6000 '
               'User=1000 EUID=0 ParentImage="/usr/bin/bash"')
CAPSET = ('action=capset Effective=0x200000 Permitted=0x200000 Image="/tmp/x" Comm="x" PID=6003 PPID=6000 '
          'User=1000 EUID=1000 ParentImage="/usr/bin/bash"')
MODULE = ('action=load Module="/tmp/diamorphine.ko" Params="" Image="/usr/bin/kmod" Comm="insmod" '
          'PID=7001 PPID=7000 User=0 EUID=0')
MODULE_MEMORY = ('action=load_memory Size=40960 Params="" Image="/tmp/dropper" Comm="dropper" '
                 'PID=7002 PPID=7000 User=0 EUID=0')
MODULE_MEMORY_INSMOD = ('action=load_memory Size=40960 Params="" Image="/bin/busybox" Comm="insmod" '
                        'PID=7003 PPID=7000 User=0 EUID=0')
EXIT = 'ExitCode=-1 Signal=9 Image="/usr/bin/sleep" Comm="sleep" PID=8001 PPID=8000 User=0 EUID=0'
MEMFD = 'MemfdName="pulseaudio" Flags=0x3 Image="/usr/bin/pulseaudio" Comm="pulseaudio" PID=9001 PPID=1 User=1000 EUID=1000'

SIGMAHQ_STYLE = """
title: Test File Deleted By Shred
id: test-shred
logsource:
  product: linux
  category: file_delete
detection:
  selection:
    Image|endswith: /shred
    TargetFilename|startswith: /var/log/
  condition: selection
level: high
"""

SIGMAHQ_CREATE = """
title: Test Tee To Preload
id: test-tee
logsource:
  product: linux
  category: file_event
detection:
  selection:
    Image|endswith: /tee
  condition: selection
level: low
"""


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    import yaml
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml") + [SIGMAHQ_STYLE, SIGMAHQ_CREATE])
    assert not sig.load_errors, sig.load_errors
    return sig


def titles(decoders, rules, log_type, line):
    event, name = decoders.decode_named(log_type, line)
    assert name == log_type, (log_type, name)
    view = dict(event, raw_message=line, log_type=log_type, hostname="srv1")
    return sorted(m["title"] for m in asyncio.run(rules.evaluate(view)))


@pytest.mark.parametrize("log_type,line,fields", [
    ("linux_file_event", FILE_KEYS, {"TargetFilename": "/root/.ssh/authorized_keys", "SourceFilename": "/root/.ssh/k.tmp",
                                     "process.executable": "/usr/bin/mv", "file.action": "rename", "event.category": "file"}),
    ("linux_fileless_exec", FILELESS, {"Image": "/memfd:e2e-payload", "process.command_line": "/proc/self/fd/4",
                                       "process.parent.executable": "/tmp/.x/loader", "event.action": "fileless_exec"}),
    ("linux_ptrace", PTRACE_ATTACH, {"ptrace.request": "attach", "ptrace.target.executable": "/usr/sbin/sshd",
                                     "ptrace.target.pid": "812"}),
    ("linux_privilege_change", SETUID_EXPLOIT, {"privilege.call": "setuid", "privilege.ids": "0", "user.id": "1000"}),
    ("linux_kernel_module", MODULE, {"module.action": "load", "module.name": "/tmp/diamorphine.ko"}),
    ("linux_process_exit", EXIT, {"process.exit_code": "-1", "process.exit_signal": "9", "event.action": "process_exit"}),
    ("linux_memfd_create", MEMFD, {"memfd.name": "pulseaudio", "process.executable": "/usr/bin/pulseaudio"}),
])
def test_lines_decode(decoders, log_type, line, fields):
    event, name = decoders.decode_named(log_type, line)
    assert name == log_type
    for key, value in fields.items():
        assert event.get(key) == value, (key, event.get(key))


@pytest.mark.parametrize("log_type,line,expected", [
    ("linux_fileless_exec", FILELESS, ["Fileless Process Execution On Linux"]),
    ("linux_ptrace", PTRACE_ATTACH, ["Process Injection Via Ptrace On Linux"]),
    ("linux_ptrace", PTRACE_GDB, []),
    ("linux_ptrace", PTRACE_POKE_GDB, []),
    ("linux_privilege_change", SETUID_EXPLOIT, ["Unexpected Privilege Change To Root On Linux"]),
    ("linux_privilege_change", SETUID_SUDO, []),
    ("linux_privilege_change", CAPSET, []),
    ("linux_kernel_module", MODULE, ["Kernel Module Loaded On Linux"]),
    ("linux_kernel_module", MODULE_MEMORY, ["Kernel Module Loaded From Memory On Linux"]),
    ("linux_kernel_module", MODULE_MEMORY_INSMOD, []),
    ("linux_file_event", FILE_CREATE, ["Linux LD Preload Hijack File Written", "Test Tee To Preload"]),
    ("linux_file_event", FILE_KEYS, []),  # a rename is file_rename, not file_event
    ("linux_file_event", FILE_DELETE, ["Test File Deleted By Shred"]),
    ("linux_process_exit", EXIT, []),
    ("linux_memfd_create", MEMFD, []),
])
def test_rules(decoders, rules, log_type, line, expected):
    assert titles(decoders, rules, log_type, line) == expected


def test_authorized_keys_written_in_place(decoders, rules):
    line = FILE_KEYS.replace("action=rename", "action=write").replace(' SourceFilename="/root/.ssh/k.tmp"', "")
    assert titles(decoders, rules, "linux_file_event", line) == ["SSH Authorized Keys Modified On Linux"]
