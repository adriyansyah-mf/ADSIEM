# Agent self-update

Agents update themselves from the server: an operator picks a version per
group and opens it ring by ring (Environment → Agent updates). Agents report
their update status on every heartbeat. A rollout pauses by itself when agents
fail.

## Trust model

The server chooses *which* signed release a group runs. It cannot choose *what
is in it*:

- The release workflow signs a manifest per package with an ed25519 key. The
  manifest covers product, version, OS, architecture, format (deb, rpm or msi),
  file name, SHA-256 and size. The signature is stored in `<package>.sig`.
- The agent verifies the manifest with the keys it trusts. Those are built into
  the binary (`-X main.UpdateKeys`), plus any keys in `update.trusted_keys` in its
  local config. It then checks that the manifest matches the offer, its own
  platform and its installer. Only then does it download, and it checks the
  download against the signed size and SHA-256 before running the installer.
- The server never sees the private key. A compromised server, or anyone with
  admin rights on it, can only offer packages that were signed already.
- With `AGENT_UPDATE_PUBLIC_KEYS` set, the server also checks each package and
  never offers one its keys do not verify. This is defense in depth; the agent
  checks either way.

**Residual risk:** a compromised server can move a group to an *older* signed
version. Rollback needs this, so it is allowed. To limit the exposure, remove
old vulnerable releases from the package directory, and rotate the signing key
if older releases must never run again. A host that must never update itself
sets `update.disabled: true`.

## One-time setup

1. Make a key pair. Keep the private key offline or in a secret store only:

   ```bash
   cd agent && go run ./cmd/siem-update-sign keygen -out update.key
   # prints the public key (base64) and its key id
   ```

2. In GitHub, set the repository **variable** `AGENT_UPDATE_PUBLIC_KEYS` to the
   public key, and the repository **secret** `AGENT_UPDATE_SIGNING_KEY` to the
   contents of `update.key`. The release workflow (`agent-release.yml`) then
   builds agents that trust the key and signs every deb, rpm and msi. It fails
   if the variable is set and the secret is missing, because the agents it
   builds could then never be updated. Several public keys can be listed,
   separated by commas, to rotate keys.

3. Optional: set `AGENT_UPDATE_PUBLIC_KEYS` on server-api to the same value, so
   the server refuses packages that do not verify.

Agents built before a key existed trust nothing. Install a release built with
the key once by hand (or add the key to `update.trusted_keys` in the agent's
config); after that, updates are automatic.

### Self-built packages (package-builder)

`package-builder` builds packages into the `agent_packages` volume. To make
them updatable:

```bash
docker compose build --build-arg UPDATE_KEYS="<public key>" package-builder   # agents trust the key
docker compose run --rm -e SIEM_UPDATE_SIGNING_KEY="$(cat update.key)" package-builder   # packages signed
```

The private key is only in the container's environment; it is never baked into
the image.

Each build moves the previous build's signed packages to `archive/` in the
volume. The deploy wizard serves only the newest build, while rollouts can
still offer, and roll back to, the archived ones. The released MSI is
downloaded together with its `.sig`.

## Running a rollout

1. Put canary agents in ring 0 and early adopters in ring 1 (the agent table on
   the page, or `PUT /api/agents/{id}` with `update_ring`). Every other agent is
   in ring 2.
2. **Set target**: choose the group and the version. The rollout starts at
   ring 0, and ring 0 agents install the version on their next heartbeat.
3. Wait until ring 0 reports *Updated*, then **Open ring 1**, then ring 2.
4. **Pause** stops new offers. Agents that are already installing finish.
5. **Rollback**: set an older version as the target. The rollout starts again
   at ring 0. The MSI allows downgrades and dpkg/rpm install the older
   package (`rpm -U --oldpackage`).
6. **Stop updates** removes the group's policy; agents keep the version they run.

The same actions are available through the API, with `agents:manage`, scoped to
the operator's group:

| Action | Request |
|---|---|
| Set the target | `PUT /api/agent-updates/policies/{group}` with `{"target_version": "1.9.0", "max_failures": 1}` |
| Open the next ring | `POST /api/agent-updates/policies/{group}/advance` |
| Pause / resume | `POST /api/agent-updates/policies/{group}/pause` and `/resume` |
| Retry | `POST /api/agent-updates/policies/{group}/retry` (new revision, unpauses) |
| Stop updates | `DELETE /api/agent-updates/policies/{group}` |
| State | `GET /api/agent-updates/policies`, `GET /api/agent-updates/packages` |

Each change is recorded in the audit log.

### Which agents get an offer

An agent gets an offer only if all of these hold:

- it is approved and not isolated;
- its ring is open;
- it does not already run the target version;
- it reports an update status from a package install (deb, rpm or msi);
- a signed package exists for its OS, architecture and format.

The page shows the reason behind each count: *Older agent* (no status
reported), *Unsupported* (the agent says why), *No package*, or *Waiting for
ring*.

### Failure handling

- On the agent, a failed attempt is retried after 10, then 20 minutes, three
  times per rollout revision. **Retry** starts a new revision with a fresh
  count.
- The rollout pauses as soon as `max_failures` agents (default 1) have *failed*,
  or have *stalled*: they took the offer and then sent no heartbeat for 15
  minutes. The pause reason names the first host and its error.
- If the deb or rpm installer fails, the wrapper in the transient unit starts
  `siem-agent.service` again, so the old version comes back and reports the
  error with the end of the installer's output. Windows Installer rolls a
  failed MSI transaction back to the installed version, service included.
- An upgrade stops the service, and the agent reports that stop with reason
  `agent_update`. An agent that does not come back raises the usual "agent
  stopped" alert.
- Upgrades are not reported as tampering. The server sets a new integrity
  baseline whenever the version changes.

## How it installs

| Platform | Installer | Notes |
|---|---|---|
| deb | `dpkg --force-confold --force-confdef -i` | Runs in a `systemd-run` transient unit, so it survives the service stop that prerm causes. The agent's `config.yaml` (its token) is kept. |
| rpm | `rpm -U --oldpackage --replacepkgs` | Same transient unit. `%config(noreplace)` keeps the config. |
| msi | `msiexec /i … /qn /norestart /l*v` | Started detached, so it outlives the service. A pending reboot (3010) counts as success; the agent never reboots the host. |

The Windows zip install and source builds report *Unsupported*: there is no
installer to upgrade them with.

Files on the agent, in its state directory:

| Path | Content |
|---|---|
| `update/state.json` | The current attempt. The process that starts after an install reads it to report *Updated* or *Failed*. |
| `update/install.log` | Output of the last installer run. |
| `update/pkg/` | The verified download. Cleared at the next start. |

## Evidence

- `agent/internal/update` unit tests cover: rejecting a tampered manifest, an
  unknown key, a platform or format mismatch, a version the manifest does not
  name, an oversized or altered download; the outcome after a restart; backoff
  and attempt limits; the transient-unit wrapper.
- `tests/server-api/test_agent_update.int.py` covers ring gating, which agents
  get offers, auto-pause on failed and stalled agents, retry revisions,
  rollback from `archive/`, server-side key checks, path and permission scoping,
  and unapproved agents.
- `deb-update` (CI) and `msi-update` (Windows agent workflow) install real
  packages on the runner. A package signed by an untrusted key is refused before
  download, the signed package upgrades the running service, and offering the
  older version again rolls it back.
