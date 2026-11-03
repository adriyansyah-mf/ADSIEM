# Script scanning

The agent scans scripts as they run with the enabled YARA rules (the YARA page, including the built-in pack: PowerShell download cradles, AMSI bypass, reverse shells, miners...). Group policy `script_scan`: `off`, `detect` (default) or `block`.

| | Windows | Linux |
|---|---|---|
| Source | AMSI's ETW provider (Microsoft-Antimalware-Scan-Interface, event 1101): what PowerShell, VBScript, JScript, Office VBA and .NET handed to AMSI, **after deobfuscation** | every start of an interpreter (sh, bash, dash, zsh, ksh, busybox, python, perl, ruby, php, node, pwsh, lua): its `-c` / `-e` / `-r` code, or the script file it was given (first 1 MB) |
| Block | the host process is terminated right after the script was scanned (it ran for a moment) | the interpreter is killed (SIGKILL) |
| Not seen | scripts of engines that do not use AMSI | code read from stdin (`curl ... \| sh`: the download rule sees the curl) |

Why not an AMSI provider DLL: Windows 10 1903+ loads only Authenticode-signed providers, and the DLL would run inside every PowerShell; the ETW provider needs neither.

- Block stops the process only for **high and critical** rules; low and medium are reported.
- The same content is scanned once per 10 minutes (PowerShell scans each block more than once). Scans run on their own goroutine with a queue of 256; a full queue drops scripts rather than slow the sensors.
- Exclusions with the **Script scanning** scope (Policies page) skip a host program, a script file or a content hash.
- The line carries the rule names, the content SHA-256 and an excerpt of at most 160 characters around the first match: never the whole script (it may hold secrets).
- Signed-in Windows users get a pop-up when a script is stopped or a high / critical rule matched.
- `etw.disabled_events: [amsi]` turns the Windows source off.

Log type `script_scan`: `script.action` (detected, terminated), `script.severity`, `script.app`, `script.rules`, `script.excerpt`, `script.name`, `file.hash.sha256`, `process.executable`, `process.pid`. Rules: Malicious Script Content (critical: high / critical match not stopped), Malicious Script Stopped (high), Suspicious Script Content (medium).

## Tests

- `agent/internal/scriptscan`: the built-in pack against a download cradle (detect), an AMSI bypass (block: killed), a reverse shell; harmless PowerShell stays quiet; dedupe, exclusions, off; interpreter argument parsing; the excerpt is short and clean.
- `agent/internal/winsensor`: AMSI event decoding (UTF-16 content, binary .NET content); native Windows (CI): `TestSensorReportsAMSIContent` runs PowerShell with a marker built at run time and requires the deobfuscated content from AMSI.
- `agent/internal/procexec`: `TestExecHookGetsArgv` (real kernel) gets `[sh -c echo <marker>]`.
- `tests/worker/test_script_scan.py`: decoder and the three alerts.
