<#
.SYNOPSIS
  Self-update through the installed service on a real Windows host (CI:
  windows-latest). Both MSIs are built trusting the same update key and signed
  with siem-update-sign; the mock SIEM offers them like server-api's rollout.

  Install -Old → an offer signed by an unknown key is refused (nothing
  installed) → the signed -New offer upgrades the running service → offering
  -Old again rolls back (an MSI downgrade) → uninstall.

  pwsh tests\windows\update-msi.ps1 -Old <old.msi> -New <new.msi> -Signer <siem-update-sign.exe>
#>
param(
    [Parameter(Mandatory)][string]$Old,
    [Parameter(Mandatory)][string]$New,
    [Parameter(Mandatory)][string]$Signer
)
$ErrorActionPreference = "Stop"

$Old = (Resolve-Path $Old).Path; $New = (Resolve-Path $New).Path; $Signer = (Resolve-Path $Signer).Path
$work = Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) "siem-update"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$mockOut = Join-Path $work "mock"
$dataDir = Join-Path $env:ProgramData "SIEMAgent"
$port = 18090
$oldVersion = ([IO.Path]::GetFileName($Old) -replace '^siem-agent-(.+)-x64\.msi$', '$1')
$newVersion = ([IO.Path]::GetFileName($New) -replace '^siem-agent-(.+)-x64\.msi$', '$1')

function Show-Diagnostics {
    Write-Host "---- agent.log"; Get-Content (Join-Path $dataDir "agent.log") -Tail 80 -ErrorAction SilentlyContinue
    Write-Host "---- update state"; Get-Content (Join-Path $dataDir "update\state.json") -ErrorAction SilentlyContinue
    Write-Host "---- last heartbeats"; Get-Content (Join-Path $mockOut "heartbeats.jsonl") -Tail 5 -ErrorAction SilentlyContinue
    Write-Host "---- update install.log (errors)"
    Select-String -Path (Join-Path $dataDir "update\install.log") -Pattern "error|failed|return value 3" -ErrorAction SilentlyContinue |
        Select-Object -Last 30 | ForEach-Object { $_.Line }
}

function Fail([string]$msg) { Show-Diagnostics; throw "UPDATE TEST FAILED: $msg" }

function Invoke-Msiexec([string[]]$msiArgs, [string]$logName) {
    $log = Join-Path $work $logName
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList ($msiArgs + @("/qn", "/l*v", "`"$log`""))
    return $p.ExitCode
}

function Get-Heartbeats {
    $f = Join-Path $mockOut "heartbeats.jsonl"
    if (-not (Test-Path $f)) { return @() }
    return @(Get-Content $f | ConvertFrom-Json)
}

# Waits for a heartbeat matching $cond (a scriptblock over one heartbeat) that
# arrived after $after heartbeats.
function Wait-Heartbeat([scriptblock]$cond, [int]$after, [int]$seconds, [string]$what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $hb = Get-Heartbeats | Select-Object -Skip $after | Where-Object $cond | Select-Object -First 1
        if ($hb) { return $hb }
        Start-Sleep 3
    }
    Fail "timed out waiting for $what"
}

# The offer server-api's heartbeat would carry (services/agent_update.offer_for).
function Set-Offer([string]$msi, [int]$revision, [string]$sigPath = "$msi.sig") {
    $signed = Get-Content $sigPath -Raw | ConvertFrom-Json
    $name = [IO.Path]::GetFileName($msi)
    $offer = @{ version = ($name -replace '^siem-agent-(.+)-x64\.msi$', '$1'); revision = $revision
                url = "/api/agent/update/package/$name"; signed = $signed }
    $offer | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $mockOut "update_offer.json") -Encoding ascii
}

$pkgDir = Join-Path $work "packages"
New-Item -ItemType Directory -Force -Path $pkgDir, $mockOut | Out-Null
Copy-Item $Old, "$Old.sig", $New, "$New.sig" $pkgDir
$env:MOCK_UPDATE_DIR = $pkgDir
$env:MOCK_FLOW = ""
$mock = Start-Process python -PassThru -NoNewWindow -ArgumentList @("tests\windows\mock_siem.py", $port, "`"$mockOut`"")
try {
    Start-Sleep 2
    # Fast heartbeats: the config written before install survives -configure.
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    Set-Content -Path (Join-Path $dataDir "config.yaml") -Value "server:`n  heartbeat_interval: 5" -Encoding ascii

    $code = Invoke-Msiexec @("/i", "`"$Old`"", "SERVER_URL=http://127.0.0.1:$port", "ENROLLMENT_KEY=ci-update-key-123",
                             "AGENT_NAME=ci-update") "install-old.log"
    if ($code -ne 0) { Fail "msiexec /i $Old exited $code" }
    (Get-Service SIEMAgent).WaitForStatus("Running", "00:00:30")
    $hb = Wait-Heartbeat { $_.version -eq $oldVersion -and $_.update.kind -eq "msi" -and $_.update.state -eq "idle" } 0 90 "$oldVersion reporting an MSI install"
    Write-Host "ok: $oldVersion installed, self-update ready (kind $($hb.update.kind), $($hb.update.os)/$($hb.update.arch))"

    # 1. A package signed by a key the agent does not trust: refused before any download.
    $rogue = Join-Path $work "rogue"
    New-Item -ItemType Directory -Force -Path $rogue | Out-Null
    & $Signer keygen -out (Join-Path $rogue "key") | Out-Null
    $rogueMsi = Join-Path $rogue ([IO.Path]::GetFileName($New))
    Copy-Item $New $rogueMsi
    & $Signer sign -key (Join-Path $rogue "key") $rogueMsi | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "signing with the rogue key failed" }
    $seen = (Get-Heartbeats).Count
    Set-Offer $New 1 "$rogueMsi.sig"
    $hb = Wait-Heartbeat { $_.update.state -eq "failed" -and $_.update.revision -eq 1 } $seen 60 "the rogue offer to fail"
    if ($hb.update.error -notmatch "trusted update key") { Fail "rogue offer failed for another reason: $($hb.update.error)" }
    if ($hb.version -ne $oldVersion) { Fail "agent version changed to $($hb.version) on a rogue offer" }
    if (Test-Path (Join-Path $mockOut "downloads.jsonl")) { Fail "the agent downloaded a package it could not verify" }
    Write-Host "ok: package signed by an untrusted key refused: $($hb.update.error)"

    # 2. The real upgrade, through the running service (a new revision: a retry).
    $seen = (Get-Heartbeats).Count
    Set-Offer $New 2
    $hb = Wait-Heartbeat { $_.version -eq $newVersion -and $_.update.state -eq "updated" } $seen 300 "the upgrade to $newVersion"
    $stops = Get-Heartbeats | Select-Object -Skip $seen | Where-Object { $_.status -eq "stopping" }
    if (-not ($stops | Where-Object { $_.reason -eq "agent_update" })) { Fail "no stop reported as agent_update during the upgrade" }
    if ((Get-Service SIEMAgent).Status -ne "Running") { Fail "service not running after the upgrade" }
    $installed = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object { $_.DisplayName -eq "SIEM Agent" }
    if (@($installed).Count -ne 1 -or $installed.DisplayVersion -ne $newVersion) {
        Fail "installed products after upgrade: $(@($installed | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" }) -join ', ')"
    }
    Write-Host "ok: upgraded $oldVersion -> $newVersion through the service (one product registered, stop reported as agent_update)"

    # 3. Rollback: the rollout targets the older version again.
    $seen = (Get-Heartbeats).Count
    Set-Offer $Old 3
    $hb = Wait-Heartbeat { $_.version -eq $oldVersion -and $_.update.state -eq "updated" } $seen 300 "the rollback to $oldVersion"
    $installed = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object { $_.DisplayName -eq "SIEM Agent" }
    if (@($installed).Count -ne 1 -or $installed.DisplayVersion -ne $oldVersion) { Fail "rollback left $($installed.DisplayVersion)" }
    Write-Host "ok: rolled back $newVersion -> $oldVersion (MSI downgrade)"

    Remove-Item (Join-Path $mockOut "update_offer.json")
    $code = Invoke-Msiexec @("/x", "`"$Old`"", "UNINSTALL_TOKEN=SMOKE-UNINS-TALLT-OKEN1") "uninstall.log"
    if ($code -ne 0) { Fail "uninstall exited $code" }
    if (Get-Service SIEMAgent -ErrorAction SilentlyContinue) { Fail "service left after uninstall" }
    Write-Host "UPDATE TEST PASSED"
}
finally {
    Stop-Process -Id $mock.Id -Force -ErrorAction SilentlyContinue
}
