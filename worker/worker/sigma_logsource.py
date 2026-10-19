# worker/worker/sigma_logsource.py
"""Which Sigma `logsource` an event belongs to, and the field names it exposes.

The platform's equivalent of a pySigma processing pipeline. Each Source says
which events carry a product/service/category — by log_type glob plus optional
field conditions — so a rule is only evaluated against events from the log
source it was written for (SigmaHQ's `windows/process_creation` never sees an
SSH line). Sources can also expose the raw key=value pairs of the line and
alias Sigma's field names onto the decoded event.

Any log_type also gets a derived source `<product>_<service>` (linux_auth →
product linux, service auth), so custom decoders work without touching this
table.
"""
import fnmatch
from dataclasses import dataclass
from typing import Any

from worker.decoder_engine import _parse_kv as parse_kv


@dataclass(frozen=True)
class Source:
    product: str | None = None
    service: str | None = None
    category: str | None = None
    log_types: tuple[str, ...] = ()
    # ((field, op, values), ...): all must hold; op is "eq" or "contains", case-insensitive
    when: tuple = ()
    raw_kv: bool = False
    # ((sigma_field, event_field, transform), ...); transform: None, "path" or "query"
    aliases: tuple = ()


def logsource_matches(logsource: dict, src: Source) -> bool:
    """A rule's logsource selects src when every key the rule sets is equal."""
    for key in ("product", "service", "category"):
        want = logsource.get(key)
        if want is not None and str(want).lower() != (getattr(src, key) or ""):
            return False
    return True


def has_logsource(logsource: dict | None) -> bool:
    return bool(logsource) and any(logsource.get(k) for k in ("product", "service", "category"))


# ─── Windows ─────────────────────────────────────────────────────

_WIN = ("windows*",)
_SYSMON = "Microsoft-Windows-Sysmon/Operational"
_PS = "Microsoft-Windows-PowerShell/Operational"
_PS_CLASSIC = "Windows PowerShell"

# Sigma service → event log channel(s), as in pySigma's windows pipeline.
WINDOWS_CHANNELS: dict[str, tuple[str, ...]] = {
    "security": ("Security",),
    "system": ("System",),
    "application": ("Application",),
    "sysmon": (_SYSMON,),
    "powershell": (_PS,),
    "powershell-classic": (_PS_CLASSIC,),
    "taskscheduler": ("Microsoft-Windows-TaskScheduler/Operational",),
    "wmi": ("Microsoft-Windows-WMI-Activity/Operational",),
    "windefend": ("Microsoft-Windows-Windows Defender/Operational",),
    "dns-server": ("DNS Server",),
    "dns-client": ("Microsoft-Windows-DNS Client Events/Operational", "Microsoft-Windows-DNS-Client/Operational"),
    "driver-framework": ("Microsoft-Windows-DriverFrameworks-UserMode/Operational",),
    "ntlm": ("Microsoft-Windows-NTLM/Operational",),
    "dhcp": ("Microsoft-Windows-DHCP-Server/Operational",),
    "applocker": ("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL",
                  "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                  "Microsoft-Windows-AppLocker/Packaged app-Execution"),
    "msexchange-management": ("MSExchange Management",),
    "printservice-admin": ("Microsoft-Windows-PrintService/Admin",),
    "printservice-operational": ("Microsoft-Windows-PrintService/Operational",),
    "smbclient-security": ("Microsoft-Windows-SmbClient/Security",),
    "smbclient-connectivity": ("Microsoft-Windows-SmbClient/Connectivity",),
    "codeintegrity-operational": ("Microsoft-Windows-CodeIntegrity/Operational",),
    "firewall-as": ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",),
    "bits-client": ("Microsoft-Windows-Bits-Client/Operational",),
    "security-mitigations": ("Microsoft-Windows-Security-Mitigations/Kernel Mode",
                             "Microsoft-Windows-Security-Mitigations/User Mode"),
    "terminalservices-localsessionmanager": ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",),
    "appxdeployment-server": ("Microsoft-Windows-AppXDeploymentServer/Operational",),
    "appxpackaging-om": ("Microsoft-Windows-AppxPackaging/Operational",),
    "appmodel-runtime": ("Microsoft-Windows-AppModel-Runtime/Admin",),
    "lsa-server": ("Microsoft-Windows-LSA/Operational",),
    "diagnosis-scripted": ("Microsoft-Windows-Diagnosis-Scripted/Operational",),
    "shell-core": ("Microsoft-Windows-Shell-Core/Operational",),
    "openssh": ("OpenSSH/Operational",),
    "ldap": ("Microsoft-Windows-LDAP-Client/Debug",),
    "vhdmp": ("Microsoft-Windows-VHDMP/Operational",),
    "capi2": ("Microsoft-Windows-CAPI2/Operational",),
    "certificateservicesclient-lifecycle-system": (
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",),
    "ntfs": ("Microsoft-Windows-Ntfs/Operational",),
    "kernel-shimengine": ("Microsoft-Windows-Kernel-ShimEngine/Operational",),
    "sense": ("Microsoft-Windows-SENSE/Operational",),
    "iis-configuration": ("Microsoft-IIS-Configuration/Operational",),
    "bitlocker": ("Microsoft-Windows-BitLocker/BitLocker Management",),
    "hyper-v-worker": ("Microsoft-Windows-Hyper-V-Worker-Admin",),
    "kernel-event-tracing": ("Microsoft-Windows-Kernel-EventTracing/Admin",),
}

# Sigma category → Sysmon event IDs (+ extra conditions), as in pySigma's sysmon pipeline.
SYSMON_CATEGORIES: dict[str, tuple[tuple[str, ...], tuple]] = {
    "process_creation": (("1",), ()),
    "file_change": (("2",), ()),
    "network_connection": (("3",), ()),
    "sysmon_status": (("4", "16"), ()),
    "process_termination": (("5",), ()),
    "driver_load": (("6",), ()),
    "image_load": (("7",), ()),
    "create_remote_thread": (("8",), ()),
    "raw_access_thread": (("9",), ()),
    "process_access": (("10",), ()),
    "file_event": (("11",), ()),
    "registry_add": (("12",), (("EventType", "eq", ("CreateKey",)),)),
    "registry_delete": (("12",), (("EventType", "eq", ("DeleteKey", "DeleteValue")),)),
    "registry_set": (("13",), ()),
    "registry_rename": (("14",), ()),
    "registry_event": (("12", "13", "14"), ()),
    "create_stream_hash": (("15",), ()),
    "pipe_created": (("17", "18"), ()),
    "wmi_event": (("19", "20", "21"), ()),
    "dns_query": (("22",), ()),
    "file_delete": (("23", "26"), ()),
    "clipboard_capture": (("24",), ()),
    "process_tampering": (("25",), ()),
    "file_delete_detected": (("26",), ()),
    "file_block_executable": (("27",), ()),
    "file_block_shredding": (("28",), ()),
    "file_executable_detected": (("29",), ()),
    "sysmon_error": (("255",), ()),
}

_WIN_ALIASES = (("Provider_Name", "Provider", None),)


def _windows_sources() -> list[Source]:
    out = [Source("windows", log_types=_WIN, raw_kv=True, aliases=_WIN_ALIASES),
           Source("windows", "powershell-classic", log_types=("windows_powershell_classic",),
                  raw_kv=True, aliases=_WIN_ALIASES)]
    for service, channels in WINDOWS_CHANNELS.items():
        out.append(Source("windows", service, log_types=_WIN, when=(("Channel", "eq", channels),),
                          raw_kv=True, aliases=_WIN_ALIASES))
    # Categories are a channel plus event IDs. Logs that reach us without a
    # Channel field (e.g. forwarded as text) still carry the canonical log_type.
    categories = [(c, _SYSMON, "windows_sysmon", ids, extra) for c, (ids, extra) in SYSMON_CATEGORIES.items()]
    categories += [
        # Security 4688 is process creation too; its decoder maps Image/CommandLine/ParentImage/User.
        ("process_creation", "Security", "windows_security", ("4688",), ()),
        ("ps_script", _PS, "windows_powershell", ("4104",), ()),
        ("ps_module", _PS, "windows_powershell", ("4103",), ()),
        ("ps_classic_start", _PS_CLASSIC, "windows_powershell_classic", ("400",), ()),
        ("ps_classic_provider_start", _PS_CLASSIC, "windows_powershell_classic", ("600",), ()),
        ("ps_classic_script", _PS_CLASSIC, "windows_powershell_classic", ("800",), ()),
    ]
    for category, channel, log_type, ids, extra in categories:
        out.append(Source("windows", None, category, log_types=_WIN,
                          when=(("Channel", "eq", (channel,)), ("EventID", "eq", ids), *extra),
                          raw_kv=True, aliases=_WIN_ALIASES))
        out.append(Source("windows", None, category, log_types=(log_type,),
                          when=(("EventID", "eq", ids), *extra), raw_kv=True, aliases=_WIN_ALIASES))
    return out


# ─── Linux, web, network ─────────────────────────────────────────

_LINUX = ("linux_*", "syslog")
_AUTH = ("linux_auth", "syslog")
_WEB = ("nginx_access*", "apache_access*")
_FW = ("fortigate_traffic", "linux_iptables")

_WEB_ALIASES = (
    ("c-ip", "source.ip", None),
    ("cs-method", "http.request.method", None),
    ("cs-uri-stem", "url.path", "path"),
    ("cs-uri-query", "url.path", "query"),
    ("sc-status", "http.response.status_code", None),
    ("cs-user-agent", "user_agent.original", None),
    ("cs-referer", "url.referrer", None),
    ("cs-username", "user.name", None),
)

SOURCES: list[Source] = [
    *_windows_sources(),
    Source("linux", log_types=_LINUX),
    Source("linux", "auth", log_types=_AUTH),
    Source("linux", "syslog", log_types=_AUTH),
    Source("linux", "sshd", log_types=_AUTH, when=(("raw_message", "contains", ("sshd[",)),)),
    Source("linux", "sudo", log_types=_AUTH, when=(("raw_message", "contains", ("sudo:", "sudo[")),)),
    Source("linux", "cron", log_types=_AUTH, when=(("raw_message", "contains", ("CRON[", "crond[")),)),
    Source("linux", "auditd", log_types=("linux_audit",), raw_kv=True),
    Source("linux", None, "process_creation", log_types=("linux_process_exec",), raw_kv=True),
    Source("nginx", None, "webserver", log_types=("nginx_access*",), aliases=_WEB_ALIASES),
    Source("apache", None, "webserver", log_types=("apache_access*",), aliases=_WEB_ALIASES),
    Source(None, None, "firewall", log_types=_FW),
    # FortiGate syslog carries traffic, event and utm records in one stream
    Source("fortigate", log_types=("fortigate_*",), raw_kv=True),
    Source("fortigate", "event", log_types=("fortigate_*",), when=(("type", "eq", ("event",)),), raw_kv=True),
    Source("fortigate", "utm", log_types=("fortigate_*",), when=(("type", "eq", ("utm",)),), raw_kv=True),
    # The platform's own rules predate this table and use these as products.
    Source("webserver", log_types=_WEB, aliases=_WEB_ALIASES),
    Source("firewall", log_types=_FW),
]


def derived_source(log_type: str) -> Source:
    product, _, service = log_type.lower().partition("_")
    return Source(product or None, service or None, log_types=(log_type,))


def sources_for_log_type(log_type: str) -> list[Source]:
    lt = log_type.lower()
    return [s for s in SOURCES if any(fnmatch.fnmatchcase(lt, g) for g in s.log_types)] + [derived_source(lt)]


def is_collected(logsource: dict | None, log_types: list[str] | set[str]) -> bool:
    """Whether a rule's logsource can see events from any of these log_types."""
    if not has_logsource(logsource):
        return True
    return any(logsource_matches(logsource, s) for lt in log_types for s in sources_for_log_type(lt))


# ─── Per-event helpers ───────────────────────────────────────────

def when_holds(src: Source, event: dict) -> bool:
    for field_name, op, values in src.when:
        v = event.get(field_name)
        if v is None:
            return False
        s = str(v).lower()
        if op == "eq":
            if not any(s == w.lower() for w in values):
                return False
        elif not any(w.lower() in s for w in values):
            return False
    return True


def apply_aliases(view: dict, aliases: tuple) -> None:
    for sigma_field, event_field, transform in aliases:
        if sigma_field in view:
            continue
        v: Any = view.get(event_field)
        if v is None:
            continue
        if transform == "path":
            v = str(v).split("?", 1)[0]
        elif transform == "query":
            parts = str(v).split("?", 1)
            if len(parts) < 2:
                continue
            v = parts[1]
        view[sigma_field] = v
