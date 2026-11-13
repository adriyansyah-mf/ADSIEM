# Windows App Control (WDAC)

Linux agents refuse a blocked program before it runs (BPF LSM). Windows agents without a driver can only terminate it right after its start shows up in ETW. App Control closes that gap: the agent turns the execution prevention block rules into a Windows App Control (WDAC) policy, and Windows itself refuses the program.

## Turning it on

Policies → **Windows App Control**: `off` (default), `audit` (Windows logs what it would block, CodeIntegrity 3076; nothing is stopped), `enforce` (blocked, CodeIntegrity 3077). Start with audit and check the `App Control Would Block A Program (Audit)` alerts.

## What the policy holds

`agent/internal/appcontrol` builds it from Windows' own `AllowAll.xml` example plus deny rules, so **everything not named still runs**; a wrong rule cannot lock a host out.

- `path` block rules: FilePath deny for that executable.
- `dir` block rules: FilePath deny for `<dir>\*`.
- `hash` block rules cannot be translated (WDAC matches Authenticode hashes; the rules hold file SHA-256). Instead, every file a hash rule or the known-malware set terminated is **learned** (up to 500, `appcontrol/appcontrol.json` in the state dir) and denied by its Authenticode hash from then on: the first start is killed, later ones never run.
- `parent` rules and detect-only rules are not part of it.

One fixed policy id (`{5B4F2A6C-9D1E-4F3A-8C7B-2E6D1A0F9C35}`, name `SIEM Agent App Control`) is replaced on every change. The agent rebuilds it only when the plan changes (rules, learned files, mode), with the ConfigCI cmdlets, and activates it with `CiTool --update-policy` (Windows 11 22H2+, Server 2025) or, without CiTool, by copying it to `CodeIntegrity\CiPolicies\Active` and calling the `PS_UpdateAndCompareCIPolicy` CIM method. `off` removes it: immediately with CiTool, otherwise at the next reboot (`method=reboot`).

## Events and alerts

- `app_control` lines from the agent: `app_control_applied`, `app_control_removed`, `app_control_failed` (rule `Agent Could Not Apply App Control Policy`, medium). A failed plan is retried every 30 minutes; prevention keeps terminating matches meanwhile.
- A program refused before it runs leaves no process start, only CodeIntegrity events. The packaged Windows config collects `eventlog:Microsoft-Windows-CodeIntegrity/Operational` (log type `windows_codeintegrity`); agents enrolled earlier need that log source added. Rules: `App Control Blocked A Program` (3077), `App Control Would Block A Program (Audit)` (3076).

## Limits

- Needs the ConfigCI PowerShell module (Windows 10 1903+ / Server 2019+ editions that ship it); where it is missing the agent reports `app_control_failed`.
- FilePath rules apply to user-mode code; drivers are out of scope.
- Paths are taken as they are; rules with Linux paths are ignored on Windows.

Tests: `agent/internal/appcontrol` (plan, script content, PowerShell parser check where `pwsh` exists, controller behaviour), `tests/worker/test_app_control.py`, and `TestAppControlEnforcesAPathRule` (enforces a real policy against a copy of `whoami.exe`) on the windows-agent runner.
