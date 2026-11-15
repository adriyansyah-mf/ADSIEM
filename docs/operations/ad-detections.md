# Active Directory attack detections

Rules for the attacks that take over a Windows domain. They read the
domain controllers' Security log, which the Windows agent ships with every
EventData field under its own name. Install the agent on every DC.

| Rule (`rules/`) | Level | Event | Catches |
|---|---|---|---|
| `win_ad_kerberoasting`: Kerberos Service Ticket Requested With RC4 | medium | 4769 | an RC4/DES service ticket for a user account's SPN (T1558.003) |
| `win_ad_kerberoasting`: Kerberoasting, many RC4 tickets | high | 4769 | ≥ 5 different SPNs from one source in 10 min |
| `win_ad_asrep_roasting`: AS-REP Roasting | high | 4768 | TGT issued without pre-authentication, RC4 (T1558.004) |
| `win_ad_asrep_roasting`: Account Made AS-REP Roastable | high | 4738 | "Don't Require Preauth" enabled on an account |
| `win_ad_dcsync`: DCSync | critical | 4662 | replication rights used by a non-DC account (T1003.006) |
| `win_ad_password_spray`: Password Spraying | high | 4625, 4771 | ≥ 10 different accounts failing from one source in 10 min (T1110.003) |
| `win_ad_persistence`: SPN Added To A User Account | medium | 5136 | targeted Kerberoasting set-up |
| `win_ad_persistence`: SID History Added | high | 4765, 4766 | SID-history injection (T1134.005) |
| `win_ad_persistence`: DSRM Password Changed | high | 4794 | DC local admin backdoor |
| `win_admin_group_member_added` (existing) | high | 4728, 4732, 4756 | additions to Domain/Enterprise/Schema Admins |

## Audit policy on the domain controllers

Windows does not log all of these by default. Set them in the **Default
Domain Controllers Policy** under Computer Configuration → Policies →
Windows Settings → Security Settings → Advanced Audit Policy Configuration:

| Subcategory | Setting | Needed for |
|---|---|---|
| Account Logon → Kerberos Service Ticket Operations | Success, Failure | 4769 |
| Account Logon → Kerberos Authentication Service | Success, Failure | 4768, 4771 |
| Logon/Logoff → Logon | Failure | 4625 |
| DS Access → Directory Service Access | Success | 4662 (DCSync). Also add an auditing entry (SACL) on the domain object for "Replicating Directory Changes" |
| DS Access → Directory Service Changes | Success | 5136 |
| Account Management → User Account Management | Success | 4738, 4765, 4766, 4794 |
| Account Management → Security Group Management | Success | 4728, 4732, 4756 |

Check what is active with `auditpol /get /category:*` on a DC.

## Tuning

- **RC4 tickets:** an old service that cannot do AES requests RC4 on every
  use, which raises the medium rule over and over. Move the service account
  to AES (`msDS-SupportedEncryptionTypes`), or add a rule exclusion for that
  `ServiceName`. The burst rule still fires for real Kerberoasting.
- **DCSync:** domain controllers (accounts ending in `$`) and Azure AD
  Connect (`MSOL_*`) are excluded. Add any other sanctioned replication
  account the same way.
- **Golden tickets** are not covered: the Security log alone does not show
  them reliably.

Tests: `tests/worker/test_ad_rules.py` runs every rule on Security lines in
the agent's format, with routine domain activity that must stay quiet.
