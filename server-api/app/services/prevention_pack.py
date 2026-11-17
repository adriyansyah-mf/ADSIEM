# server-api/app/services/prevention_pack.py
"""Built-in execution prevention rules, added disabled: a pack of signer
rules for VPN and anonymizer clients (Windows). An analyst turns on the
ones the organisation does not allow; an approved company VPN stays off.

Every publisher below is the Authenticode signer of the vendor's official
Windows installer, read with agent/cmd/authsig on 17 Nov 2026 (the version
in each description). A vendor that changes its signing certificate's name
needs a new rule. Re-check with:

    go run ./cmd/authsig <installer.exe>        (from agent/)

Seeding only adds rules whose name is missing: an analyst's toggle, edit or
deletion of a pack rule is never undone."""
from __future__ import annotations

from sqlalchemy import text

PACK_PREFIX = "VPN pack: "

# (name, publisher, description)
VPN_SIGNERS: list[tuple[str, str, str]] = [
    ("NordVPN", "nordvpn s.a.",
     "NordVPN client and installer (NordVPNSetup.exe from downloads.nordcdn.com)."),
    ("Surfshark", "Surfshark B.V.",
     "Surfshark client and installer (SurfsharkSetup.exe from downloads.surfshark.com)."),
    ("ProtonVPN", "Proton AG",
     "ProtonVPN client and installer (ProtonVPN_v5.1.9_x64.exe, GitHub ProtonVPN/win-app). Proton AG also signs "
     "Proton Mail, Drive and Pass: this rule stops those too."),
    ("Mullvad VPN", "Mullvad VPN AB",
     "Mullvad VPN client and installer (MullvadVPN-2026.5_x64.exe, GitHub mullvad/mullvadvpn-app)."),
    ("WireGuard", "WireGuard LLC",
     "WireGuard client and installer (wireguard-installer.exe from download.wireguard.com). Leave off where the "
     "company VPN is WireGuard."),
    ("Psiphon", "Psiphon Inc.",
     "Psiphon circumvention client (psiphon3.exe from psiphon.ca): a portable program, run from any folder."),
    ("Tor Browser", "THE TOR PROJECT, INC.",
     "Tor Browser (tor-browser-windows-x86_64-portable-16.0.1.exe from dist.torproject.org): portable, run from "
     "any folder. The Tor exit feed on the IP Blocklist stops its traffic as well."),
]


def pack_rules() -> list[dict]:
    return [{"name": PACK_PREFIX + name, "rule_type": "signer", "value": publisher, "action": "block",
             "description": f"{desc} Signer rule (Windows): every program this publisher signed, any version, "
                            "any folder; with App Control enforce, refused before it runs. Built-in pack, off by default."}
            for name, publisher, desc in VPN_SIGNERS]


async def seed_pack(db) -> int:
    """Adds the pack rules that are missing, disabled. Commits. Returns how many were added."""
    added = 0
    for r in pack_rules():
        res = await db.execute(text(
            "INSERT INTO exec_prevention_rules (id, name, description, rule_type, value, parent, action, is_enabled, "
            "created_at) VALUES (gen_random_uuid(), :name, :description, :rule_type, :value, '', :action, false, now()) "
            "ON CONFLICT (name) DO NOTHING"), r)
        added += res.rowcount or 0
    await db.commit()
    return added
