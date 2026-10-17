# server-api/app/core/url_guard.py
"""Outbound-URL safety checks (SSRF prevention) for user-supplied webhook URLs."""
import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException, status

from app.core.config import settings

_ALLOWED_SCHEMES = {"http", "https"}


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_outbound_url(url: str | None) -> None:
    """Reject webhook URLs that target loopback, link-local, or private ranges.

    Raises HTTPException(422) for a malformed URL or a disallowed scheme/target,
    unless ALLOW_PRIVATE_WEBHOOK_TARGETS is enabled for trusted deployments.
    """
    if url is None:
        return
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Webhook URL must use http:// or https://")
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Webhook URL has no host")

    if settings.ALLOW_PRIVATE_WEBHOOK_TARGETS:
        return

    try:
        addrinfos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Webhook host cannot be resolved: {host}")

    for family, _type, _proto, _canon, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Webhook URL targets a disallowed (private/loopback/link-local) address: {ip_str}",
            )
