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

# Embed a version resource (File Properties → Details: company, description,
# version). Without it the exe looks anonymous to Defender's heuristics.
# goversioninfo writes a .syso that go build links in; it is deleted after the build.
$nums = [regex]::Matches($Version, '\d+') | ForEach-Object { [int]$_.Value }
$ver = @(0, 0, 0, 0)
for ($i = 0; $i -lt [Math]::Min(4, $nums.Count); $i++) { $ver[$i] = $nums[$i] }
$vi = Get-Content -Raw "packaging\windows\versioninfo.json" | ConvertFrom-Json
foreach ($key in "FileVersion", "ProductVersion") {
    $vi.FixedFileInfo.$key = [pscustomobject]@{ Major = $ver[0]; Minor = $ver[1]; Patch = $ver[2]; Build = $ver[3] }
}
$vi.StringFileInfo.FileVersion = $ver -join "."
$vi.StringFileInfo.ProductVersion = $ver -join "."
$viDir = Join-Path ([IO.Path]::GetTempPath()) "siem-versioninfo"
New-Item -ItemType Directory -Force -Path $viDir | Out-Null
$vi | ConvertTo-Json -Depth 6 | Set-Content -Path "$viDir\versioninfo.json" -Encoding ASCII
$agentDir = (Get-Location).Path
$syso = Join-Path $agentDir "cmd\agent\resource_windows_amd64.syso"
Push-Location $viDir
try {
    go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.0 -64 -o $syso
    if ($LASTEXITCODE -ne 0) { throw "goversioninfo failed" }
} finally { Pop-Location }

try {
    go build -ldflags "-s -w -X main.Version=$Version -X main.UpdateKeys=$env:UPDATE_KEYS" -o "$bin\siem-agent.exe" .\cmd\agent\
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $syso
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $viDir
}

$out = "dist\packages\siem-agent-$Version-x64.msi"
wix build packaging\windows\siem-agent.wxs -arch x64 -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "BinDir=$bin" -o $out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Write-Host "built $out"
