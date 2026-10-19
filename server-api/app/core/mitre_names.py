# server-api/app/core/mitre_names.py
"""MITRE ATT&CK technique names for the IDs the platform's rules, UEBA and
heuristics emit, so an alert can show "T1110.003 Brute Force: Password
Spraying (Credential Access)" instead of a bare code. Unknown IDs still render,
just without a name."""
import re

from app.core.mitre_tactics import TACTIC_MAP

TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping", "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1005": "Data from Local System", "T1014": "Rootkit", "T1018": "Remote System Discovery",
    "T1020": "Automated Exfiltration", "T1021": "Remote Services", "T1021.004": "Remote Services: SSH",
    "T1027": "Obfuscated Files or Information", "T1029": "Scheduled Transfer", "T1036": "Masquerading",
    "T1041": "Exfiltration Over C2 Channel", "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol", "T1053": "Scheduled Task/Job",
    "T1053.003": "Scheduled Task/Job: Cron", "T1055": "Process Injection", "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1068": "Exploitation for Privilege Escalation", "T1070": "Indicator Removal",
    "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
    "T1070.003": "Indicator Removal: Clear Command History", "T1071": "Application Layer Protocol",
    "T1074": "Data Staged", "T1078": "Valid Accounts", "T1078.002": "Valid Accounts: Domain Accounts",
    "T1078.003": "Valid Accounts: Local Accounts", "T1080": "Taint Shared Content",
    "T1082": "System Information Discovery", "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery", "T1090": "Proxy", "T1091": "Replication Through Removable Media",
    "T1095": "Non-Application Layer Protocol", "T1098": "Account Manipulation",
    "T1098.004": "Account Manipulation: SSH Authorized Keys", "T1102": "Web Service",
    "T1105": "Ingress Tool Transfer", "T1110": "Brute Force", "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying", "T1114": "Email Collection", "T1129": "Shared Modules",
    "T1132": "Data Encoding", "T1133": "External Remote Services", "T1134": "Access Token Manipulation",
    "T1136": "Create Account", "T1136.001": "Create Account: Local Account",
    "T1140": "Deobfuscate/Decode Files or Information", "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise", "T1199": "Trusted Relationship", "T1200": "Hardware Additions",
    "T1203": "Exploitation for Client Execution", "T1204": "User Execution",
    "T1218": "System Binary Proxy Execution", "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop", "T1490": "Inhibit System Recovery",
    "T1496": "Resource Hijacking", "T1498": "Network Denial of Service", "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component", "T1505.003": "Server Software Component: Web Shell",
    "T1518": "Software Discovery", "T1543": "Create or Modify System Process",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1546": "Event Triggered Execution", "T1547": "Boot or Logon Autostart Execution",
    "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1550": "Use Alternate Authentication Material", "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.004": "Unsecured Credentials: Private Keys", "T1554": "Compromise Host Software Binary",
    "T1555": "Credentials from Password Stores", "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting", "T1560": "Archive Collected Data",
    "T1561": "Disk Wipe", "T1562": "Impair Defenses", "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1566": "Phishing", "T1567": "Exfiltration Over Web Service", "T1569": "System Services",
    "T1569.002": "System Services: Service Execution", "T1572": "Protocol Tunneling",
    "T1589": "Gather Victim Identity Information", "T1589.002": "Gather Victim Identity Information: Email Addresses",
    "T1590": "Gather Victim Network Information", "T1591": "Gather Victim Org Information",
    "T1592": "Gather Victim Host Information", "T1595": "Active Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning", "T1596": "Search Open Technical Databases",
    "T1597": "Search Closed Sources", "T1598": "Phishing for Information",
    "T1621": "Multi-Factor Authentication Request Generation",
}

_ID = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def technique_info(entry: str) -> dict:
    """'T1110.003' or 'T1110.003: Password Spraying' → {id, name, tactic, url}."""
    m = _ID.search(str(entry))
    if not m:
        return {"id": str(entry), "name": None, "tactic": None, "url": None}
    code = m.group(0).upper()
    given = str(entry).split(":", 1)[1].strip() if ":" in str(entry) else None
    return {
        "id": code,
        "name": TECHNIQUE_NAMES.get(code) or TECHNIQUE_NAMES.get(code.split(".")[0]) or given,
        "tactic": TACTIC_MAP.get(code.split(".")[0]),
        "url": f"https://attack.mitre.org/techniques/{code.replace('.', '/')}/",
    }
