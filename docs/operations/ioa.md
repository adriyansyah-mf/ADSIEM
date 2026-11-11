# Indicators of attack (IOA): behaviour chains

The agent's IOA engine (`agent/internal/ioa`, agent 1.23.0+) follows process
trees for ordered chains of behaviour and reports a chain once every step was
seen. It reads the telemetry the sensors already produce (Windows ETW, Linux
eBPF), so it needs no driver and runs the same on both OSes.

**Detect only.** A match raises an alert (`ioa_detection` → `rules/ioa_*.yaml`);
nothing is stopped. Blocking comes later, rule by rule, once a rule has run in
detect mode without false positives across the fleet.

## Rules

| ID | Chain | OS | Level |
|---|---|---|---|
| `ioa_office_child_internet` | Office app → script host / LOLBin → public connection from that child's tree | Windows | high |
| `ioa_office_drop_exec` | Office app writes an executable or script → that file is started (by anyone) | Windows | high |
| `ioa_script_host_download_exec` | wscript/cscript/mshta on a user-folder or URL script → internet → starts a program | Windows | high |
| `ioa_powershell_download_child` | encoded / hidden / download-cradle PowerShell → internet → starts or writes a program | Windows | medium |
| `ioa_lsass_access_from_shell` | program started from a shell, script host or user folder → opens LSASS with VM_READ | Windows | critical |
| `ioa_userdir_exe_injection` | program from a user folder → remote thread / write+thread access into another program | Windows | medium |
| `ioa_download_then_exec` | certutil, bitsadmin, curl, wget, … → writes into a temp / user folder → that file runs | both | high |
| `ioa_webserver_shell` | web server → shell → recon tool, public connection or dropped program | both | high |
| `ioa_reverse_shell` | shell / interpreter with socket arguments (`/dev/tcp`, `nc -e`, `pty.spawn`, `TCPClient`) → connects out | both | critical |
| `ioa_tmp_exec_injection` | program from /tmp, /dev/shm, /var/tmp → ptrace or writes another process's memory | Linux | high |
| `ioa_tmp_exec_root` | non-root user runs a program from a temp folder → it sets its uid/gid to 0 | Linux | high |
| `ioa_dev_project_dropper` | node / npm / python / bun / deno runs a project → writes a script or program into a hidden home folder (`~/.n2/`) or temp → it runs (as a program or the interpreter's argument) | both | high |
| `ioa_dev_odd_port` | project interpreter → public address on a port projects rarely use (not web, git, DNS, common databases) | both | medium |
| `ioa_dev_credential_read` | project interpreter or user-folder program → opens a credential store it does not own | both | high |

Each rule has a time window from its first step (2–30 minutes). One alert per
rule and program pair every 15 minutes per agent. The alert's `ioa.chain`
lists each step with the process, pid and what it did.

## Developer compromise (fake job interviews)

North Korean groups (TraderTraitor / Lazarus: the Bybit and the October 2026
Binance thefts) get in through a developer: a fake recruiter has them run a
"coding test" project, whose code drops a hidden stage, steals browser,
wallet, SSH and cloud credentials and calls home. The three `ioa_dev_*`
rules follow that chain, fed by a sensor of its own:

**Credential store access** (`agent/internal/credwatch`, log type
`credential_access`): a program opening a credential store it does not own.

| Store | What |
|---|---|
| `browser_passwords`, `browser_cookies`, `browser_master_key` | Chromium (Chrome, Edge, Brave, Vivaldi, Opera) Login Data / Web Data, Cookies, Local State; Firefox logins.json, key4.db, cookies.sqlite |
| `wallet_extension`, `wallet_file` | MetaMask, Phantom, Coinbase, Binance, Trust, OKX, Rabby, Keplr, Ronin… extension storage; Exodus, Electrum, Ethereum keystore, Solana id.json, Bitcoin wallets |
| `ssh_key`, `cloud_credentials`, `token_file`, `gpg_key` | `~/.ssh/id_*`, AWS/Azure/gcloud/kubeconfig/Docker, .git-credentials / .npmrc / .netrc / .pypirc, GPG private keys |

The owner (the browser for its profile, ssh/git for keys, the cloud CLI)
and indexers, backup and antivirus are never reported; one line per process
and store every 10 minutes. Windows reads the Kernel-File opens the ETW
sensor already receives; Linux puts fanotify marks on the stores of every
login user (rescanned every 10 minutes; `linux_sensor.disabled_events:
[credential]` turns it off). Alerts: browser/wallet stores at medium,
keys/tokens at low (`rules/credential_store_*.yaml`).

To check an endpoint end to end, run `tests/simulations/dev_compromise_sim.sh`
there as a normal user: it reproduces the chain harmlessly (a node project
writes `~/.adsiem-sim/stage.py`, runs it with python, the stage opens one
byte of an SSH key or browser file and connects to portquiz.net:1224). Expect
`IOA:` alerts for the three `ioa_dev_*` rules within a minute.

## Turning it off, excluding programs

Policies → group → **Behaviour chains (IOA)**: Detect (default) or Off.

False positives (deployment tools, admin scripts, a web app that legitimately
shells out): add an exclusion with the **Behaviour (IOA)** scope. It is
checked against both the process that started the chain and the one that
completed it: program (image), path prefix or command-line substring.

## Rollout

1. Deploy agent 1.23.0+; IOA runs in detect mode by default.
2. Watch `IOA:` alerts for one to two weeks. Note which programs trigger
   which rules on legitimate activity and exclude them per group.
3. A rule with no legitimate hits across the fleet is a candidate for a block
   mode (suspend the chain's process tree), which will be added per rule.

## Limits

- Windows has no pre-execution veto without a kernel driver: when block mode
  comes it will stop the chain right after the step is seen (ETW latency:
  milliseconds to a second), not before.
- Linux network lines name the process by pid only; a connection from a
  forked child that never exec'd is not tied to its tree.
- Linux exec paths are what was passed to execve; a relative path (`./x`) is
  matched against the dropped file by its tail.
