<#
.SYNOPSIS
  Installs (or upgrades) the SIEM agent as the SIEMAgent Windows service.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1 -ServerUrl http://siem.example.com:8000 -EnrollmentToken <token>

  Run from an elevated prompt in the folder that holds siem-agent.exe.
  On upgrade the existing config (and its agent token) is kept; omit both
  parameters to just replace the binary.
#>
param(
    [string]$ServerUrl,
    [string]$EnrollmentToken,
    [string]$Group = "default",
    [switch]$EnableAuditing
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}

$installDir = Join-Path $env:ProgramFiles "SIEMAgent"
$dataDir    = Join-Path $env:ProgramData "SIEMAgent"
$exe        = Join-Path $installDir "siem-agent.exe"
$config     = Join-Path $dataDir "config.yaml"
$source     = Join-Path $PSScriptRoot "siem-agent.exe"

if (-not (Test-Path $source)) { throw "siem-agent.exe not found next to install.ps1" }

New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null

$existing = Get-Service -Name SIEMAgent -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
    Write-Host "Stopping existing SIEMAgent service..."
    Stop-Service -Name SIEMAgent -Force
    (Get-Service SIEMAgent).WaitForStatus("Stopped", "00:00:30")
}

Copy-Item -Force $source $exe

if (-not (Test-Path $config)) {
    if (-not $ServerUrl -or -not $EnrollmentToken) {
        throw "First install needs -ServerUrl and -EnrollmentToken."
    }
    $template = Get-Content -Raw (Join-Path $PSScriptRoot "config.yaml")
    $template = $template -replace 'url: http://your-siem-server:8000', ("url: " + $ServerUrl)
    $template = $template -replace 'enrollment_token: ""', ('enrollment_token: "' + $EnrollmentToken + '"')
    $template = $template -replace 'group: default', ("group: " + $Group)
    Set-Content -Path $config -Value $template -Encoding ASCII
    Write-Host "Wrote $config"
} elseif ($ServerUrl -or $EnrollmentToken) {
    Write-Host "Keeping existing $config (delete it to re-enroll)."
}

# The config holds the agent token: SYSTEM and Administrators only.
icacls $dataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

if ($EnableAuditing) {
    # Logon, process creation (with command line) and account management events.
    auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null  # Logon
    auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null                  # Process Creation
    auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null  # User Account Management
    auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null                  # Security Group Management
    auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null                  # Other Object Access (scheduled tasks)
    auditpol /set /subcategory:"{0CCE9233-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null                  # Filtering Platform Policy Change (WFP filters)
    $audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Force -Path $audit | Out-Null
    Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
    $sbl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Force -Path $sbl | Out-Null
    Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Write-Host "Enabled logon/process/account auditing and PowerShell script block logging."
}

if (-not $existing) {
    & $exe -install -config $config
    if ($LASTEXITCODE -ne 0) { throw "siem-agent.exe -install failed ($LASTEXITCODE)" }
}

Start-Service -Name SIEMAgent
Write-Host "SIEMAgent is running. Log: $dataDir\agent.log"
