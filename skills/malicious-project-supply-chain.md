---
name: malicious-project-supply-chain
description: A developer opened or ran a malicious code project or package - "Malicious-Looking Project Downloaded", project code run by an interpreter dropping a hidden program, a project interpreter (node, python) connecting to a public address on an unusual port or reading a credential store, VS Code tasks that auto-run, or a poisoned npm/pip dependency. Common in fake job interviews and test tasks. Finds what ran and which secrets were exposed.
---

# Malicious project and supply-chain investigation

Fake "test tasks" in job interviews, cloned repositories and poisoned
packages run code the moment a developer opens or installs them. Their
targets are the developer's secrets: browser passwords, crypto wallets,
SSH keys, cloud tokens and source code access.

## 1. The project and what triggered it
- The project scan alert (log type `project_scan`) names the folder, the
  origin URL and the findings: an auto-run VS Code task
  (`.vscode/tasks.json` with `runOn: folderOpen`), obfuscated JavaScript
  in a config or test file, install scripts (`postinstall` in
  package.json, `setup.py` actions), and binary blobs.
- `run_artifact Generic.Collectors.File` on the flagged files (tasks.json,
  package.json, the obfuscated file) to quote the trigger.
- `process_tree` for the interpreter (node, python, npm) started from the
  project folder: its children, the files it wrote, and the hosts it
  contacted.

## 2. What ran and what it took
- Dropped programs: the IOA "dropped a hidden program and ran it". Use
  `run_artifact Windows.Search.ExecutablesInUserFolders` or
  `Linux.Search.FileFinder` on the home folder, then hash and check them.
- Credential theft: the IOA "read a credential store" / "Browser or Wallet
  Credential Store Read". List which stores: browser profiles, wallet
  extensions, `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.npmrc`, `.env`
  files.
- Exfiltration: `Windows.Network.Netstat` / `Linux.Network.Netstat` and
  `search_events` for the interpreter's outbound connections (often an IP
  on an unusual port, or a paste/file-sharing service).
- Persistence: `Linux.Sys.Persistence` / `Windows.Sys.Persistence`.

## 3. Reach
- Other developers who cloned the same origin URL or installed the same
  package version (`search_events` / `search_alerts` across hosts for the
  repository URL, folder name and hashes).
- The secrets' reach: repositories and CI the stolen tokens can push to,
  and cloud accounts the keys open.

## Verdict
- **True positive:** project code that auto-runs, is obfuscated, drops a
  program, contacts an unknown address, or reads credential stores.
- **False positive:** a legitimate project whose build legitimately
  downloads dependencies or tools from known registries (npmjs, PyPI,
  GitHub releases). Check the destinations and that nothing touched
  credential stores.

## Report must cover
The project (origin URL, folder, trigger file and line), what ran, the
secrets exposed (by store), where data went, persistence found, and the
other developers affected. The recommended actions: isolate the host, rotate
**every** exposed secret (browser-saved passwords, SSH keys, cloud and git
tokens, wallet seeds moved to a new wallet), revoke sessions, block the
C2, and warn the team about the lure.
