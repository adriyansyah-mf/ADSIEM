# tests/worker/test_dvwa_lab_logs.py
"""MySQL general log, PHP error log and Apache error log: lines captured from
a DVWA lab (Ubuntu 26.04, MariaDB 11.8, PHP 8.5, Apache 2.4.66) must decode
and fire the shipped rules, and the application's own queries must not."""
import asyncio
import glob
import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")


@pytest.fixture(scope="module")
def engines():
    import yaml
    decs = sorted((open(p).read() for p in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))),
                  key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decs)
    sig = SigmaEngine()
    sig.load_from_yaml_list([open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, "rules/*.yaml")))])
    assert not sig.load_errors, sig.load_errors
    return dec, sig


_hosts = itertools.count()


def run(engines, log_type, line):
    dec, sig = engines
    event, name = dec.decode_named(log_type, line)
    # Suppression is keyed on source.ip, else hostname: a host per event keeps
    # one case's alert from muting the next.
    host = f"dvwa-lab-{next(_hosts)}"
    matches = asyncio.run(sig.evaluate(dict(event, raw_message=line, log_type=log_type, hostname=host)))
    return event, name, {m["title"] for m in matches}


# ─── MySQL general log ────────────────────────────────────────────

SQLI = "SQL Injection Reached Database Query"


@pytest.mark.parametrize("line", [
    "\t\t    49 Query\tSELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT user,password FROM users-- -'",
    "\t\t    41 Query\tSELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1'",
    "\t\t    53 Query\tSELECT first_name, last_name FROM users WHERE user_id = '1' AND SLEEP(1)-- -'",
    "261104 11:22:57\t    49 Query\tSELECT first_name FROM users WHERE user_id = '-1' union all select 1,@@version#'",
    "\t\t    49 Query\tSELECT first_name FROM users WHERE user_id = '1' or 1=1 -- '",
    "\t\t    49 Query\tSELECT first_name FROM users WHERE user_id = '1' AND extractvalue(1,concat(0x7e,version()))-- -'",
])
def test_injected_queries_fire(engines, line):
    event, name, titles = run(engines, "mysql_general", line)
    assert name == "mysql_general_query"
    assert event["event.action"] == "db_query" and event["db.operation"] == "Query"
    assert event["db.statement"].startswith("SELECT")
    assert SQLI in titles


@pytest.mark.parametrize("line", [
    # DVWA's own login and lookup queries
    "\t\t    47 Query\tSELECT * FROM `users` WHERE user='admin' AND password='5f4dcc3b5aa765d61d8327deb882cf99'",
    "\t\t    49 Query\tSELECT first_name, last_name FROM users WHERE user_id = '1'",
    "\t\t    49 Query\tUSE dvwa",
    "261104 11:13:17\t     3 Query\tSET SQL_LOG_BIN=0, WSREP_ON=OFF",
    "\t\t    47 Query\tSELECT table_schema, table_name, create_time",
    "\t\t    47 Query\tINSERT INTO guestbook VALUES ('1','This is a test comment.','test')",
])
def test_application_queries_do_not_fire(engines, line):
    _, name, titles = run(engines, "mysql_general", line)
    assert name == "mysql_general_query"
    assert SQLI not in titles


def test_mysql_access_denied_and_connect(engines):
    event, name, _ = run(engines, "mysql_general",
                         "\t\t    61 Connect\tAccess denied for user 'dvwa'@'localhost' (using password: YES)")
    assert name == "mysql_general_access_denied"
    assert event["event.action"] == "db_login_failed" and event["event.outcome"] == "failure"
    assert event["user.name"] == "dvwa" and event["source.address"] == "localhost"
    assert event["db.auth.used_password"] == "YES"

    event, name, _ = run(engines, "mysql_general", "\t\t    62 Connect\tAccess denied for user 'admin'@'localhost'")
    assert name == "mysql_general_access_denied" and event["user.name"] == "admin"

    event, name, _ = run(engines, "mysql_general", "261104 11:23:58\t    59 Connect\tdvwa@localhost on dvwa using TCP/IP")
    assert name == "mysql_general_connect"
    assert (event["user.name"], event["source.address"], event["db.name"], event["network.transport"]) == \
        ("dvwa", "localhost", "dvwa", "TCP/IP")

    event, name, _ = run(engines, "mysql_general", "\t\t    49 Connect\tdvwa@localhost on  using TCP/IP")
    assert name == "mysql_general_connect" and event["db.name"] == ""


def test_mysql_other_commands(engines):
    event, name, _ = run(engines, "mysql_general", "261104 11:22:57\t    53 Quit\t")
    assert name == "mysql_general_command" and event["db.operation"] == "Quit"
    event, name, _ = run(engines, "mysql_general", "\t\t    54 Quit")  # trailing tab stripped by the shipper
    assert name == "mysql_general_command" and event["db.operation"] == "Quit"
    event, name, _ = run(engines, "mysql_general", "\t\t    12 Init DB\tdvwa")
    assert name == "mysql_general_command" and event["db.operation"] == "Init DB" and event["db.statement"] == "dvwa"


def test_mysql_brute_force_rule_targets_failed_logins(engines):
    _, sig = engines
    rule = next(r for r in sig._rules if r.title == "MySQL Brute Force Attack")
    assert rule.logsource == {"product": "mysql"}


# ─── PHP error log ────────────────────────────────────────────────

FI = "PHP File Inclusion Attempt"


@pytest.mark.parametrize("target", [
    "../../../../etc/passwd",
    "http://198.51.100.7/shell.txt",
    "php://filter/convert.base64-encode/resource=index",
    "/etc/shadow",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
])
def test_php_include_attempts_fire(engines, target):
    line = (f"[04-Nov-2026 04:14:37 UTC] PHP Warning:  include({target}): Failed to open stream: No such file or "
            "directory in /var/www/html/dvwa/vulnerabilities/fi/index.php on line 36")
    event, name, titles = run(engines, "php_error", line)
    assert name == "php_error_include"
    assert event["php.include.target"] == target and event["php.function"] == "include"
    assert event["file.path"] == "/var/www/html/dvwa/vulnerabilities/fi/index.php"
    assert event["log.origin.file.line"] == "36" and event["log.level"] == "Warning"
    assert FI in titles


def test_php_benign_include_failure_does_not_fire(engines):
    line = ("[04-Nov-2026 04:30:00 UTC] PHP Warning:  include(file4.php): Failed to open stream: No such file or "
            "directory in /var/www/html/dvwa/vulnerabilities/fi/index.php on line 36")
    _, name, titles = run(engines, "php_error", line)
    assert name == "php_error_include" and FI not in titles


def test_php_include_followup_line_is_generic(engines):
    line = ("[04-Nov-2026 04:14:37 UTC] PHP Warning:  include(): Failed opening '../../../../etc/passwd' for "
            "inclusion (include_path='.:/usr/share/php') in /var/www/html/dvwa/vulnerabilities/fi/index.php on line 36")
    event, name, titles = run(engines, "php_error", line)
    assert name == "php_error" and event["file.path"].endswith("fi/index.php")
    assert FI not in titles  # the include(<target>) line already raised it


def test_php_sql_exception(engines):
    line = ("[04-Nov-2026 04:22:56 UTC] PHP Fatal error:  Uncaught mysqli_sql_exception: You have an error in your "
            "SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to "
            "use near ''1''' at line 1 in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php:11")
    event, name, titles = run(engines, "php_error", line)
    assert name == "php_error_sql"
    assert event["error.type"] == "mysqli_sql_exception" and event["log.level"] == "Fatal error"
    assert event["message"].startswith("You have an error in your SQL syntax")
    assert event["file.path"].endswith("sqli/source/low.php") and event["log.origin.file.line"] == "11"
    assert "Web Application SQL Error" in titles


def test_php_generic_lines(engines):
    event, name, titles = run(engines, "php_error", "[04-Nov-2026 04:13:23 UTC] PHP Deprecated:  Directive "
                              "'allow_url_include' is deprecated in Unknown on line 0")
    assert name == "php_error" and event["log.level"] == "Deprecated" and event["log.origin.file.line"] == "0"
    assert not titles & {FI, "Web Application SQL Error"}
    _, name, _ = run(engines, "php_error", "#0 /var/www/html/dvwa/vulnerabilities/sqli/source/low.php(11): mysqli_query()")
    assert name is None  # stack-trace continuation stays raw


# ─── Apache error log ─────────────────────────────────────────────

def test_apache_error_with_client(engines):
    line = ("[Wed Nov 04 11:23:58.046283 2026] [php:error] [pid 19163:tid 19163] [client 127.0.0.1:42742] "
            "script '/var/www/html/dvwa/does-not-exist.php' not found or unable to stat")
    event, name, _ = run(engines, "apache_error", line)
    assert name == "apache_error"
    assert (event["log.logger"], event["log.level"], event["process.pid"]) == ("php", "error", "19163")
    assert (event["source.ip"], event["source.port"]) == ("127.0.0.1", "42742")
    assert event["message"].startswith("script '/var/www/html/dvwa/does-not-exist.php'")


def test_apache_error_with_code(engines):
    event, name, _ = run(engines, "apache_error", "[Wed Nov 04 11:12:24.095248 2026] [mpm_event:notice] "
                         "[pid 15770:tid 15770] AH00489: Apache/2.4.66 (Ubuntu) configured -- resuming normal operations")
    assert name == "apache_error" and event["error.code"] == "AH00489" and event["source.ip"] is None
    assert event["message"] == "Apache/2.4.66 (Ubuntu) configured -- resuming normal operations"

    event, _, _ = run(engines, "apache_error", "[Wed Nov 04 12:00:00.000001 2026] [authz_core:error] [pid 1:tid 2] "
                      "[client 203.0.113.5:51000] AH01630: client denied by server configuration: /var/www/html/.git")
    assert event["error.code"] == "AH01630" and event["source.ip"] == "203.0.113.5"
    assert event["message"] == "client denied by server configuration: /var/www/html/.git"
