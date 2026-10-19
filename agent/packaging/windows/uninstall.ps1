<#
.SYNOPSIS
  Removes the SIEMAgent service and binary. -Purge also deletes the config,
  token, buffer and logs under %ProgramData%\SIEMAgent.
#>
param([switch]$Purge)

$ErrorActionPreference = "Stop"

$installDir = Join-Path $env:ProgramFiles "SIEMAgent"
$dataDir    = Join-Path $env:ProgramData "SIEMAgent"
$exe        = Join-Path $installDir "siem-agent.exe"

if (Get-Service -Name SIEMAgent -ErrorAction SilentlyContinue) {
    Stop-Service -Name SIEMAgent -Force -ErrorAction SilentlyContinue
    if (Test-Path $exe) {
        & $exe -uninstall
    } else {
        sc.exe delete SIEMAgent | Out-Null
    }
}

# Undo an isolation (and any IP blocks) the agent may have left behind.
if (Get-NetFirewallRule -DisplayName "SIEM-Isolate-*" -ErrorAction SilentlyContinue) {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
}
Get-NetFirewallRule -DisplayName "SIEM-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue }
Write-Host "SIEMAgent removed."
