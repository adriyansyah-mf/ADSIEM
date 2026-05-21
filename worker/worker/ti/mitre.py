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
