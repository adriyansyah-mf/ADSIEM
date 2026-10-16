# worker/worker/url_guard.py
"""Outbound-URL safety check (SSRF prevention) applied before webhook delivery."""
import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOW_PRIVATE_WEBHOOK_TARGETS: bool = os.environ.get(
    "ALLOW_PRIVATE_WEBHOOK_TARGETS", "false"
).lower() in ("1", "true", "yes")


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_safe_outbound_url(url: str) -> tuple[bool, str]:
    """Return (ok, reason). Rejects non-http(s) schemes and private/loopback targets."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme '{parsed.scheme}' not allowed"
    host = parsed.hostname
    if not host:
        return False, "no host"
    if ALLOW_PRIVATE_WEBHOOK_TARGETS:
        return True, ""
    try:
        addrinfos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, f"cannot resolve host '{host}'"
    for _family, _type, _proto, _canon, sockaddr in addrinfos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            return False, f"targets disallowed address {ip}"
    return True, ""
