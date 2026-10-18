<#
.SYNOPSIS
  Builds dist\packages\siem-agent-<version>-x64.msi on Windows (WiX v5 .NET tool).
  Run from agent\:  pwsh packaging\build-msi.ps1 -Version 1.5.0
#>
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = "Stop"

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version 5.0.2
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
wix extension add -g WixToolset.Util.wixext/5.0.2 | Out-Null

$bin = "dist\msi-bin"
New-Item -ItemType Directory -Force -Path $bin, "dist\packages" | Out-Null
$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags "-s -w -X main.Version=$Version" -o "$bin\siem-agent.exe" .\cmd\agent\
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

$out = "dist\packages\siem-agent-$Version-x64.msi"
wix build packaging\windows\siem-agent.wxs -arch x64 -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "BinDir=$bin" -o $out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Write-Host "built $out"
