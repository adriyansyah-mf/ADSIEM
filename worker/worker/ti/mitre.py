"""Heuristic MITRE ATT&CK T-code hints from keywords. Adapted from soc-agent."""
_KEYWORDS: dict[str, tuple[str, str]] = {
    "brute force": ("T1110", "Brute Force"),
    "bruteforce": ("T1110", "Brute Force"),
    "failed password": ("T1110", "Brute Force"),
    "powershell": ("T1059.001", "PowerShell"),
    "encodedcommand": ("T1027", "Obfuscated Files or Information"),
    "base64": ("T1027", "Obfuscated Files or Information"),
    "lateral movement": ("T1021", "Remote Services"),
    "psexec": ("T1569.002", "Service Execution"),
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "web shell": ("T1505.003", "Web Shell"),
    "kerberoast": ("T1558.003", "Kerberoasting"),
    "port scan": ("T1046", "Network Service Discovery"),
    "nmap": ("T1046", "Network Service Discovery"),
    "exfiltrat": ("T1041", "Exfiltration Over C2 Channel"),
    "phishing": ("T1566", "Phishing"),
    "c2": ("T1071", "Application Layer Protocol"),
    "command and control": ("T1071", "Application Layer Protocol"),
}


def suggest_mitre(text: str) -> list[str]:
    low = text.lower()
    seen: set[str] = set()
    out: list[str] = []
    for k, (tid, _) in _KEYWORDS.items():
        if k in low and tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


# Base technique ID (sub-technique suffix stripped) -> MITRE ATT&CK tactic.
# Vocabulary matches the kill_chain_stage enum in worker/worker/llm_client.py's
# _CAMPAIGN_SYSTEM_PROMPT, so a single alert's stage and a campaign's stage
# are comparable when both get rendered on the same attack-graph timeline.
_TACTIC_MAP: dict[str, str] = {
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


def stage_for_techniques(mitre_techniques: list[str]) -> str:
    """Kill-chain stage for the first recognized technique in the list.

    The L1 triage prompt asks the model to list the most relevant technique
    first (e.g. "T1110: Brute Force"), so the first match is treated as the
    alert's primary stage rather than trying to reconcile several tactics.
    """
    for entry in mitre_techniques or []:
        code = str(entry).split(":")[0].strip().split(".")[0].upper()
        if code in _TACTIC_MAP:
            return _TACTIC_MAP[code]
    return "Unknown"
