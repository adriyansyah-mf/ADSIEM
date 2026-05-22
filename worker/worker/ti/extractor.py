"""Extract IOC artifacts from unstructured text. Adapted from soc-agent."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse
from worker.ti.iocs import IOC, IOCType

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]+\b|\b(?:[A-Fa-f0-9]{1,4}:)+::[A-Fa-f0-9:]*\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
_URL_RE = re.compile(r"https?://[^\s`'\"<>]+", re.I)
_MD5_RE = re.compile(r"\b[a-fA-F\d]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F\d]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F\d]{64}\b")
_POWERSHELL_RE = re.compile(r"powershell[^\n]{0,40}-(?:enc(?:odedcommand)?|e)\s+[A-Za-z0-9+/=]{16,}", re.I)
_CMDLINE_SUSPICIOUS = re.compile(r"(?:cmd\.exe\s*/c|bash\s+-c|\bcurl\s+|\bwget\s+|certutil\s+-decode|\brundll32\s+|\bregsvr32\s+)", re.I)
_BOGUS_SUFFIXES = (".exe",".dll",".bat",".ps1",".html",".htm",".txt",".log",".conf",".php",".asp",".aspx",".jsp",".js",".css",".json",".xml",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".db")


def _bogus(d: str) -> bool:
    if ".exe." in d or ".dll." in d or ".bat." in d:
        return True
    return d.endswith(".db")


def extract_iocs(text: str) -> list[IOC]:
    if not text:
        return []
    findings: dict[tuple, IOC] = {}

    def add(t: IOCType, v: str, ctx: str | None = None) -> None:
        key = (t.value, v.strip())
        findings.setdefault(key, IOC(type=t, value=v.strip(), context=ctx))

    for h in _SHA256_RE.findall(text):
        add(IOCType.hash_sha256, h)
    for h in _SHA1_RE.findall(text):
        add(IOCType.hash_sha1, h)
    for h in _MD5_RE.findall(text):
        add(IOCType.hash_md5, h)

    ip_seen: set[str] = set()
    for raw in set(_IPV6_RE.findall(text)) | set(_IPV4_RE.findall(text)):
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            continue
        canon = str(parsed)
        if canon in ip_seen:
            continue
        ip_seen.add(canon)
        add(IOCType.ipv4 if parsed.version == 4 else IOCType.ipv6, canon)

    url_hosts: set[str] = set()
    for url in _URL_RE.findall(text):
        add(IOCType.url, url)
        try:
            h = urlparse(url).hostname
            if h:
                url_hosts.add(h.lower())
        except ValueError:
            pass

    for dom in _DOMAIN_RE.findall(text):
        dlow = dom.lower()
        if _bogus(dlow) or dlow in url_hosts or dlow.endswith(_BOGUS_SUFFIXES):
            continue
        add(IOCType.domain, dom)

    for m in _POWERSHELL_RE.findall(text):
        add(IOCType.powershell, m[:4096])

    for line in text.splitlines():
        if _CMDLINE_SUSPICIOUS.search(line):
            add(IOCType.command, line.strip()[:1024])

    return list(findings.values())
