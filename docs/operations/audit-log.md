# Audit log

**Administration → Audit log** records who did what, from which address and
browser, and whether it worked. Entries cannot be edited or deleted, and a
check on the same page shows whether anything was changed behind the
platform's back.

## What each entry holds

| Field | Example |
|---|---|
| Time | `2026-11-16 09:12:44` |
| User | `ana`. For a failed login, the username that was tried. Kept after the account is deleted. |
| Action | `login_failed`, `login_success`, `logout`, `permission_denied`, `mfa_enable`, `case_created`, ... |
| Result | `success`, `failure` (wrong password, bad MFA code) or `denied` (no permission, rate limit) |
| IP address | The client's address as nginx saw it (`X-Real-IP`, set from `$remote_addr`) |
| Browser / client | The User-Agent header |
| Request | `POST /api/auth/login` |
| Detail | What the action needs to explain itself, e.g. `{"reason": "bad_password"}` |

### Sign-in events

| Action | When | Detail |
|---|---|---|
| `login_failed` | Unknown user, wrong password, disabled account, wrong MFA code | `reason`: `unknown_user`, `bad_password`, `disabled_account`, `bad_mfa_code` |
| `login_rate_limited` | More than 5 logins a minute from one address | `limit` |
| `login_success` | Signed in | `mfa`: whether MFA was used |
| `logout` | Signed out | — |
| `refresh_token_rejected` | A revoked or replayed session token was presented | `reason` |
| `mfa_setup_started`, `mfa_enable`, `mfa_disable` | MFA changes, including failed attempts | `reason` on failure |
| `permission_denied` | Someone called something their role does not allow | `role` |

The person at the login screen always gets the same "Invalid credentials".
Only the audit log tells an unknown user from a wrong password.

Filter by user, IP address, result and time. Clicking an IP address shows
everything from that address. **Failed logins and errors** filters to
failures. **Export CSV** downloads what the filters show, up to 50,000
entries.

## Why entries cannot be changed

The database itself enforces this (`server-api/app/services/audit_chain.py`),
so it holds for every writer, including the worker:

1. **Append-only.** Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` on
   `audit_logs`. No API route edits or deletes an entry. Deleting a user
   leaves their entries alone: `actor_id` has no foreign key, and
   `actor_name` keeps the name.
2. **Hash chain.** On insert, a trigger gives each entry the next number
   (`seq`) and computes `hash = SHA-256(previous hash + every field of this
   entry)`. An advisory lock makes concurrent writers take turns.
3. **Checkpoint outside the database.** Every 5 minutes the worker copies the
   newest `(seq, hash)` to the Elasticsearch index `audit_checkpoints`. Each
   one is written once and never overwritten.

Someone with the database owner's rights can still switch the triggers off.
The check then finds what they did:

| Tampering | How it shows |
|---|---|
| An entry's content changed | `#N: content changed after it was written` |
| An entry in the middle deleted | `rows N-M are missing` and the next entry no longer links |
| The newest entries deleted | The checkpoint's entry is gone: `a checkpointed row is gone` |
| An entry rewritten with a new hash | Every later entry stops linking, and the checkpoint no longer matches |

The check runs when the page opens, then every 5 minutes while it stays open. **Check again** runs
it now. API: `GET /api/audit-logs/verify`. Group admins see the verdict;
superadmins also see entry numbers and the newest hash.

To beat the check, an attacker would have to rewrite every entry from the
change onwards and also the Elasticsearch checkpoints. For a stronger
guarantee, copy the newest hash off the server now and then (for example
into a shift report). A later check then proves nothing before it changed.

## Limits

- Entries written before this feature have no `seq` and sit outside the
  chain. They still cannot be edited or deleted.
- One chain covers all groups.
- Nothing ever removes audit entries. The table grows by a few hundred bytes
  per entry.
