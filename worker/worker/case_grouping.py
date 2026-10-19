# worker/worker/case_grouping.py
"""Which case an alert belongs in.

Alerts used to join any open AI case with the same source IP, and cases were
otherwise one per attacker IP — so internet-facing hosts produced a stream of
near-identical brute-force cases, and anything worse that later hit the same
host vanished into one of them as a note. Now:

- every alert gets an attack *family* (its furthest kill-chain tactic, from the
  rule's ATT&CK tags; else the triage's threat_type; else its title);
- an alert joins an open case only with the same entity (IP or host) AND family;
- a different family on an entity with an open case gets its own case, linked
  both ways — and a post-compromise family after credential access/initial
  access is raised to critical;
- failed-only brute force from public addresses goes into one digest case per
  group per day instead of one case per IP.
"""
from __future__ import annotations

import ipaddress
import re

# Kill-chain order: the alert's family is its furthest tactic.
KILL_CHAIN = [
    "reconnaissance", "resource_development", "initial_access", "credential_access", "discovery",
    "execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]
TACTIC_ALIASES = {"recon": "reconnaissance", "c2": "command_and_control"}

# Families that mean the attacker got in (after brute force / exploitation attempts).
POST_COMPROMISE = {
    "execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
}
PRE_COMPROMISE = {"reconnaissance", "credential_access", "initial_access", "discovery"}

THREAT_TYPE_FAMILY = {
    "brute_force": "credential_access", "scan": "reconnaissance", "malware": "execution",
    "c2": "command_and_control", "exfiltration": "exfiltration", "lateral_movement": "lateral_movement",
    "privilege_escalation": "privilege_escalation",
}

_TITLE_HINTS = [
    (re.compile(r"(?i)after brute|login after|successful login after"), "initial_access"),
    (re.compile(r"(?i)brute|password spray|failed (login|logon|su|sudo)|credential stuffing|account locked"),
     "credential_access"),
    (re.compile(r"(?i)scan|enumeration|probe|recon"), "reconnaissance"),
    (re.compile(r"(?i)reverse shell|webshell|command injection|rce|shellshock|log4|exploit"), "initial_access"),
    (re.compile(r"(?i)persistence|cron|scheduled task|service install|run key|authorized_keys|new user|user created"),
     "persistence"),
    (re.compile(r"(?i)sudo|privilege|admin group|root"), "privilege_escalation"),
    (re.compile(r"(?i)beacon|c2|callback"), "command_and_control"),
    (re.compile(r"(?i)exfil"), "exfiltration"),
    (re.compile(r"(?i)log cleared|disable security|tamper"), "defense_evasion"),
    (re.compile(r"(?i)powershell|process|execution|miner"), "execution"),
]


def _tactic(tag: str) -> str | None:
    t = str(tag).lower()
    if not t.startswith("attack.") or t[7:8] == "t" and t[8:9].isdigit():
        return None
    name = TACTIC_ALIASES.get(t[7:].replace("-", "_"), t[7:].replace("-", "_"))
    return name if name in KILL_CHAIN else None


def attack_family(tags: list | None = None, threat_type: str | None = None, title: str = "") -> str:
    tactics = {t for t in (_tactic(x) for x in tags or []) if t}
    if tactics:
        return max(tactics, key=KILL_CHAIN.index)
    if threat_type in THREAT_TYPE_FAMILY:
        return THREAT_TYPE_FAMILY[threat_type]
    for rx, family in _TITLE_HINTS:
        if rx.search(title or ""):
            return family
    return "other"


def is_public_ip(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def is_failed_bruteforce(tags: list | None, title: str, family: str) -> bool:
    """Password guessing that hasn't succeeded: T1110 credential access (or a
    brute-force title), not the brute-force-then-success rule."""
    if family != "credential_access":
        return False
    if re.search(r"(?i)after brute|success", title or ""):
        return False
    techniques = {str(t).lower() for t in tags or []}
    return any(t.startswith("attack.t1110") for t in techniques) or bool(
        re.search(r"(?i)brute|password spray|failed (login|logon)|user enumeration|account locked", title or ""))


def raises_to_critical(new_family: str, related_families: set[str]) -> bool:
    """A post-compromise family on an entity already under credential/initial-access attack."""
    return new_family in POST_COMPROMISE and bool(related_families & {"credential_access", "initial_access"})
