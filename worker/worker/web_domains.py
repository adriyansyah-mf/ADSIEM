# worker/worker/web_domains.py
"""Web Protection domain rules, shared by the worker (feeds, alert auto-block)
and server-api (manual blocks, agent sync). Standard library only: the
server-api image copies this one file (server-api/Dockerfile)."""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import urlsplit

MAX_DOMAIN = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HEX_LABEL = re.compile(r"^0x[0-9a-f]+$")

# (domain, include_subdomains). Shared hosting whose subdomains belong to one
# tenant protects only the apex, so evil.weebly.com stays blockable.
BUILTIN_ALLOWLIST: tuple[tuple[str, bool], ...] = (
    ("github.com", True), ("githubusercontent.com", True), ("google.com", True),
    ("googleusercontent.com", True), ("googleapis.com", True), ("gstatic.com", True),
    ("microsoft.com", True), ("live.com", True), ("office.com", True), ("sharepoint.com", True),
    ("windows.net", True), ("dropbox.com", True), ("dropboxusercontent.com", True),
    ("discordapp.com", True), ("discord.com", True), ("amazonaws.com", True), ("cloudfront.net", True),
    ("apple.com", True), ("icloud.com", True), ("cloudflare.com", True), ("akamaized.net", True),
    ("weebly.com", False), ("wixsite.com", False), ("blogspot.com", False), ("wordpress.com", False),
    ("000webhostapp.com", False), ("netlify.app", False), ("vercel.app", False), ("pages.dev", False),
    ("web.app", False), ("firebaseapp.com", False), ("herokuapp.com", False),
)


class DomainError(ValueError):
    """Why a value cannot be web-blocked; the message is shown to the analyst."""


def normalize(value: str) -> str:
    """Domain from a bare domain or URL: lowercase, no trailing dot, punycode."""
    raw = str(value or "").strip()
    if not raw:
        raise DomainError("Enter a domain or URL")
    if "://" in raw:
        try:
            host = urlsplit(raw).hostname or ""
        except ValueError as exc:
            raise DomainError("Not a valid URL") from exc
    else:
        host = raw.split("/", 1)[0].rsplit("@", 1)[-1]
        if host.count(":") == 1:
            host = host.split(":", 1)[0]
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise DomainError("IP addresses cannot be web-blocked; block the IP on the firewall instead")
    # Browsers resolve numeric shorthands (10.1, 1.2.3, 0x7f.0.0.1) as IPv4; no real TLD is numeric.
    last_label = host.rsplit(".", 1)[-1]
    if last_label.isdigit() or _HEX_LABEL.match(last_label):
        raise DomainError("IP addresses cannot be web-blocked; block the IP on the firewall instead")
    if "." not in host:
        raise DomainError("A domain needs at least two labels, like example.com")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainError("Not a valid domain name") from exc
    if len(ascii_host) > MAX_DOMAIN or not all(_LABEL.match(label) for label in ascii_host.split(".")):
        raise DomainError("Not a valid domain name")
    return ascii_host


def allow_match(domain: str, rules: Iterable[tuple[str, bool]]) -> str | None:
    """The allowlist rule (domain) that covers `domain`, or None."""
    for rule, include_subdomains in rules:
        if domain == rule or (include_subdomains and domain.endswith("." + rule)):
            return rule
    return None
