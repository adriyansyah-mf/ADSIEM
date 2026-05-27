# install-windows.ps1
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install-windows.ps1 -ServerURL http://YOUR_SERVER

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerURL,
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$Group = "default"
)

$InstallDir = "C:\ProgramData\siem-agent"
$BinaryPath = "$InstallDir\siem-agent.exe"
$ConfigPath = "$InstallDir\config.yaml"
$ServiceName = "siem-agent"

# Create install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Copy binary from same directory as script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$ScriptDir\siem-agent.exe" $BinaryPath -Force

# Write config
@"
agent:
  name: "$AgentName"
  group: "$Group"

server:
  url: "$ServerURL"
  heartbeat_interval: 30

logs:
  - path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    type: windows_security
    enabled: false
"@ | Set-Content $ConfigPath -Encoding UTF8

# Install Windows service using sc.exe
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe create $ServiceName binPath= "`"$BinaryPath`" -config `"$ConfigPath`"" start= auto DisplayName= "SIEM Platform Agent" | Out-Null
sc.exe description $ServiceName "Collects system logs and forwards them to SIEM Platform" | Out-Null
Start-Service -Name $ServiceName

$svc = Get-Service -Name $ServiceName
Write-Host "Service status: $($svc.Status)"
Write-Host "SIEM Agent installed successfully. Config: $ConfigPath"
