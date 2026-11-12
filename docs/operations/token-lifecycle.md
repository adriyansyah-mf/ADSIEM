# Token lifecycle

## Agent tokens

An agent authenticates every request with `X-Agent-Token`. The server stores
only its SHA-256 (`agents.token_hash`).

**Rotation.** Agents that support it send `token_rotation: 1` on each
heartbeat. When the token is due, the heartbeat response carries a new one in
`agent_token`. The token is due when any of these holds:

- it is older than `AGENT_TOKEN_ROTATE_DAYS` (30)
- an admin asked for a rotation
- the agent still authenticates with the previous token (it missed the new one)

The token the agent used becomes `prev_token_hash` and keeps working for
`AGENT_TOKEN_GRACE_HOURS` (72). That covers requests in flight, and a restart
before the new token reached disk. Rotation is compare-and-set on the current
token, so of two concurrent heartbeats only one rotates.

Agents without the flag are never rotated. They ignore `agent_token`, and
rotating them would lock them out once the grace ended.

**On the agent.** A rotated token is applied to every request at once and kept
in `agent.token` next to `config.yaml` (0600, written atomically).
`config.yaml` isn't rewritten: its hash is part of the tamper check. The file
also records a fingerprint of the token in `config.yaml`. If `config.yaml`
later holds a different token (edited, or reinstalled over an old config
directory), the stored token is ignored and deleted. Re-enrollment and
`siem-agent -configure -key ...` delete it too.

**Admin actions.**

```bash
# rotate on the agent's next heartbeat
curl -X POST https://siem/api/agents/<id>/rotate-token -H "Authorization: Bearer $TOKEN"
# a token leaked: rotate, and end the previous token's grace at once
curl -X POST 'https://siem/api/agents/<id>/rotate-token?revoke_previous=true' -H "Authorization: Bearer $TOKEN"
```

`revoke_previous=true` locks out an agent that hasn't picked up its new token
yet. It then needs re-enrollment. Both actions are audit-logged
(`agent_token_rotation_requested`). Rotations are logged as `agent_token_rotated`
with a reason: `age`, `requested` or `redelivery`.

## Dashboard sessions (refresh tokens)

Login sets an httponly `refresh_token` cookie (`REFRESH_TOKEN_EXPIRE_DAYS`, 7).
Its `jti` must be live in Redis (`siem:rt:<jti>`).

- **Every refresh rotates it.** The old jti stays valid for 30 seconds so that
  parallel requests and tabs don't log each other out. After that it is refused
  and the refusal is audited (`refresh_token_rejected`). A replayed old token is
  a theft signal.
- **Logout** (`POST /api/auth/logout`, called by the dashboard's sign-out)
  deletes the jti and clears the cookie.
- **Redis down:** the JWT signature and expiry still apply, so a Redis outage
  doesn't log anyone out. A token issued while Redis is down has no jti. It is
  accepted once and replaced by a tracked one. Logging out during an outage
  only clears the cookie.
- Tokens from before this change (no jti) are accepted once and replaced.
- Set `REFRESH_COOKIE_SECURE=true` when the dashboard is served over HTTPS.

Deactivating a user stops refreshes at once (`is_active` is checked). Access
tokens (`ACCESS_TOKEN_EXPIRE_MINUTES`, 15) are not revocable: they expire.
