# server-api/app/core/mitre_tactics.py
"""Base technique ID -> MITRE ATT&CK tactic. Mirrors worker/worker/ti/mitre.py's
_TACTIC_MAP (server-api and worker are separate deployables with no shared
package, so this is a deliberate duplication — keep both in sync by hand)."""

TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command & Control", "Exfiltration", "Impact",
]

TACTIC_MAP: dict[str, str] = {
    # Reconnaissance
    "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1589": "Reconnaissance",
    "T1590": "Reconnaissance", "T1591": "Reconnaissance", "T1598": "Reconnaissance",
    "T1597": "Reconnaissance", "T1596": "Reconnaissance",
    # Initial Access
    "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
    "T1133": "Initial Access", "T1200": "Initial Access", "T1091": "Initial Access",
    "T1195": "Initial Access", "T1199": "Initial Access",
    # Execution
    "T1059": "Execution", "T1203": "Execution", "T1204": "Execution", "T1129": "Execution",
    # Persistence
    "T1053": "Persistence", "T1098": "Persistence", "T1136": "Persistence",
    "T1547": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
    "T1505": "Persistence", "T1554": "Persistence",
    # Privilege Escalation
    "T1548": "Privilege Escalation", "T1068": "Privilege Escalation",
    "T1055": "Privilege Escalation", "T1134": "Privilege Escalation",
    # Defense Evasion
    "T1027": "Defense Evasion", "T1070": "Defense Evasion", "T1036": "Defense Evasion",
    "T1562": "Defense Evasion", "T1140": "Defense Evasion", "T1218": "Defense Evasion",
    "T1569": "Defense Evasion",
    # Credential Access
    "T1003": "Credential Access", "T1110": "Credential Access", "T1558": "Credential Access",
    "T1552": "Credential Access", "T1555": "Credential Access", "T1621": "Credential Access",
    # Discovery
    "T1046": "Discovery", "T1082": "Discovery", "T1087": "Discovery", "T1018": "Discovery",
    "T1057": "Discovery", "T1083": "Discovery", "T1518": "Discovery",
    # Lateral Movement
    "T1021": "Lateral Movement", "T1080": "Lateral Movement", "T1550": "Lateral Movement",
    # Collection
    "T1560": "Collection", "T1005": "Collection", "T1114": "Collection", "T1074": "Collection",
    # Command & Control
    "T1071": "Command & Control", "T1105": "Command & Control", "T1572": "Command & Control",
    "T1090": "Command & Control", "T1102": "Command & Control", "T1132": "Command & Control",
    # Exfiltration
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1029": "Exfiltration", "T1020": "Exfiltration",
    # Impact
    "T1486": "Impact", "T1490": "Impact", "T1489": "Impact", "T1496": "Impact",
    "T1485": "Impact", "T1499": "Impact", "T1561": "Impact",
}


def parse_technique(entry: str) -> tuple[str, str]:
    """Split an AI-produced 'T1110: Brute Force' entry into (code, name).
    Falls back to the raw entry as the name if there's no ':' separator."""
    raw = str(entry).strip()
    if ":" in raw:
        code, name = raw.split(":", 1)
        return code.strip().upper(), name.strip()
    return raw.upper(), raw


def tactic_for_code(code: str) -> str:
    base = code.split(".")[0].upper()
    return TACTIC_MAP.get(base, "Unknown")
