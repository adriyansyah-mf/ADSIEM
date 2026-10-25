<#
  Native Windows evidence tests: the journal (NTFS identity, ACLs, flushes),
  durable file cursors (share-delete opens, rename rotation) and Event Log
  bookmarks. The event log tests create their own classic log (SIEMxxxx),
  write markers, stop and resume from the same journal directory, clear only
  that log to prove gap recovery, and remove it afterwards. They never touch
  Security, System or another channel.

  Needs an elevated prompt (creating an event log source does).
    ./tests/windows/evidence-resume.ps1
#>
$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated prompt: the event log tests create and remove a test log."
}

$env:SIEM_NATIVE_EVENTLOG = "1"
$packages = @(
    "./agent/internal/evidence",
    "./agent/internal/buffer",
    "./agent/internal/config",
    "./agent/internal/winevent",
    "./agent/internal/tailer",
    "./agent/internal/task", # kill_process / quarantine_file / restore_file / agent_integrity on Windows
    "./agent/internal/etw",  # real ETW sessions: kernel logger and manifest providers
    "./agent/internal/winsensor", # ETW process telemetry, end to end
    "./agent/internal/firewall",  # Windows Defender Firewall backend and expiry
    "./agent/internal/update"     # self-update: MSI detection, verification
)
$failed = @()
$logs = Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) "evidence-go-test"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
foreach ($pkg in $packages) {
    Write-Host "==> go test $pkg"
    $log = Join-Path $logs (($pkg -replace '[./]+', '-').Trim('-') + ".log")
    # Every test with its duration (a slow one shows up), plus the usual failures.
    go test -count=1 -v -timeout 25m $pkg 2>&1 | Tee-Object -FilePath $log | ForEach-Object {
        if ($_ -match '^(--- (FAIL|SKIP|PASS)|FAIL|ok|panic)' -or $_ -match '_test\.go:\d+:') { Write-Host $_ }
    }
    if ($LASTEXITCODE -ne 0) {
        $failed += $pkg
        Write-Host "---- last lines of $pkg (running tests, goroutines)"
        Get-Content $log -Tail 80 | ForEach-Object { Write-Host $_ }
    }
}
if ($failed.Count -gt 0) {
    throw "native evidence tests failed: $($failed -join ', ')"
}
Write-Host "ok: native evidence, cursor and bookmark tests passed"
