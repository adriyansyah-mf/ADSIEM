# worker/worker/ip_iocs.py
"""IP IoC blocklist rules, shared by the worker (SOAR block_ioc) and server-api
(manual blocks, agent delta sync). Standard library only: the server-api image
copies this one file (server-api/Dockerfile).

Agents of a group drop traffic to and from every active entry of their group
and of the "*" (every group) list when the group policy's ip_ioc is "block",
and report connections to them as ioc_match when it is "detect" or "block"."""
from __future__ import annotations

import ipaddress

# Postgres advisory lock key ordering ip_block_seq commits: writers take it
# exclusive, the agent delta sync shared (same scheme as WEB_BLOCK_SEQ_LOCK).
IP_BLOCK_SEQ_LOCK = 0x4950424C4B
ALL_GROUPS = "*"
# Broader networks would cut off whole providers; an IoC is a host or a small range.
MIN_PREFIX_V4 = 16
MIN_PREFIX_V6 = 48
SOURCES = ("manual", "soar", "alert", "feed")

# Shared by SOAR (and any automatic source): revives a removed entry and only
# ever extends an expiry, so an automatic re-block never shortens a manual one.
UPSERT_SQL = """
INSERT INTO ip_block_entries (id, cidr, group_id, source, status, reason, alert_id,
                              created_at, updated_at, expires_at, seq)
VALUES (gen_random_uuid(), :cidr, :group, :source, 'active', :reason, :alert, now(), now(), :expires,
        nextval('ip_block_seq'))
ON CONFLICT (group_id, cidr, source) DO UPDATE
SET status = 'active', reason = EXCLUDED.reason, alert_id = COALESCE(EXCLUDED.alert_id, ip_block_entries.alert_id),
    expires_at = CASE WHEN ip_block_entries.status = 'active' AND (ip_block_entries.expires_at IS NULL
                                                                  OR EXCLUDED.expires_at IS NULL)
                      THEN NULL
                      ELSE GREATEST(ip_block_entries.expires_at, EXCLUDED.expires_at) END,
    updated_at = now(), seq = nextval('ip_block_seq')
RETURNING id, cidr
"""


class IPError(ValueError):
    """Why a value cannot be IP-blocked; the message is shown to the analyst."""


def normalize(value: str, allow_private: bool = False) -> str:
    """Canonical CIDR ("203.0.113.7/32") for an address or network.

    Refuses loopback, unspecified, multicast, link-local and reserved space,
    networks broader than /16 (IPv4) or /48 (IPv6), and private space unless
    allow_private (an analyst may block an internal host; automation may not)."""
    raw = str(value or "").strip()
    if not raw:
        raise IPError("empty value")
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise IPError(f"not an IP address or CIDR: {raw[:64]!r}") from None
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None and net.prefixlen >= 96:
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    minimum = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    if net.prefixlen < minimum:
        raise IPError(f"{net} is too broad (at most /{minimum} for IPv{net.version})")
    addr = net.network_address
    for flag, why in (("is_loopback", "loopback"), ("is_unspecified", "unspecified"),
                      ("is_multicast", "multicast"), ("is_link_local", "link-local"),
                      ("is_reserved", "reserved")):
        if getattr(addr, flag) or getattr(net.broadcast_address, flag):
            raise IPError(f"{net} is {why} address space")
    if not allow_private and (addr.is_private or not addr.is_global):
        raise IPError(f"{net} is private address space (only an analyst can block it)")
    return str(net)
