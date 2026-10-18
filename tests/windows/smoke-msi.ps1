<#
.SYNOPSIS
  End-to-end check of the Windows agent MSI on a real Windows host (CI: windows-latest).
  Install with properties → service runs → agent enrolls with the mock SIEM →
  an Application event written with eventcreate arrives as an EventID=... line →
  uninstall removes the service. Needs Administrator and python on PATH.

  pwsh tests\windows\smoke-msi.ps1 -Msi agent\dist\packages\siem-agent-0.0.1-x64.msi
#>
param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = "Stop"

$Msi = (Resolve-Path $Msi).Path
$work = Join-Path $env:RUNNER_TEMP "siem-smoke"
if (-not $env:RUNNER_TEMP) { $work = Join-Path $env:TEMP "siem-smoke" }
New-Item -ItemType Directory -Force -Path $work | Out-Null
$mockOut = Join-Path $work "mock"
$dataDir = Join-Path $env:ProgramData "SIEMAgent"
$port = 18080

function Show-Diagnostics {
    Write-Host "---- agent.log"; Get-Content (Join-Path $dataDir "agent.log") -Tail 60 -ErrorAction SilentlyContinue
    Write-Host "---- config.yaml"; Get-Content (Join-Path $dataDir "config.yaml") -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch "token" }
    Write-Host "---- received logs"; Get-Content (Join-Path $mockOut "logs.jsonl") -Tail 20 -ErrorAction SilentlyContinue
    Write-Host "---- msiexec log (errors)"; Select-String -Path (Join-Path $work "*.log") -Pattern "error|failed|return value 3" -ErrorAction SilentlyContinue |
        Select-Object -Last 30 | ForEach-Object { $_.Line }
}

function Fail([string]$msg) { Show-Diagnostics; throw "SMOKE TEST FAILED: $msg" }

function Invoke-Msiexec([string[]]$msiArgs, [string]$logName) {
    $log = Join-Path $work $logName
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList ($msiArgs + @("/qn", "/l*v", "`"$log`""))
    return $p.ExitCode
}

# The mock serves HTTPS with a self-signed certificate, like a platform on a bare IP.
$tls = Join-Path $work "tls"
python tests\windows\make_cert.py $tls
if ($LASTEXITCODE -ne 0) { throw "make_cert.py failed" }
$mock = Start-Process python -PassThru -NoNewWindow -ArgumentList @("tests\windows\mock_siem.py", $port, "`"$mockOut`"",
                                                                    "`"$tls\cert.pem`"", "`"$tls\key.pem`"")
$caCert = $null
try {
    Start-Sleep 2
    # 0. Untrusted at first; the Deploy agent wizard's trust lines (dashboard/src/lib/deployCommands.ts
    #    trustCommand) put it in LocalMachine\Root, after which PowerShell and the agent accept it.
    curl.exe -fsS -o NUL "https://127.0.0.1:$port/health" 2>$null
    if ($LASTEXITCODE -eq 0) { Fail "the self-signed mock was trusted before importing its certificate" }
    $b64 = ((Get-Content "$tls\cert.pem") -notmatch "-----") -join ""
    $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
    $st = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine'); $st.Open('ReadWrite'); $st.Add($ca); $st.Close()
    $caCert = $ca
    $health = Invoke-WebRequest -UseBasicParsing "https://127.0.0.1:$port/health"
    if ($health.StatusCode -ne 200) { Fail "health over TLS returned $($health.StatusCode)" }
    Write-Host "ok: self-signed server certificate trusted after the wizard's import"

    # 1. A first install without the server/key must fail cleanly (and roll back).
    $code = Invoke-Msiexec @("/i", "`"$Msi`"") "install-noprops.log"
    if ($code -eq 0) { Fail "install without SERVER_URL/ENROLLMENT_KEY succeeded" }
    if (Get-Service SIEMAgent -ErrorAction SilentlyContinue) { Fail "service left behind by the failed install" }
    Write-Host "ok: install without properties refused (exit $code)"

    # 2. Install the way the dashboard tells you to.
    $code = Invoke-Msiexec @("/i", "`"$Msi`"", "SERVER_URL=https://127.0.0.1:$port", "ENROLLMENT_KEY=ci-smoke-key-123",
                             "AGENT_NAME=ci-windows", "ENABLE_AUDITING=1") "install.log"
    if ($code -ne 0) { Fail "msiexec /i exited $code" }
    $svc = Get-Service SIEMAgent -ErrorAction SilentlyContinue
    if (-not $svc) { Fail "SIEMAgent service not installed" }
    $svc.WaitForStatus("Running", "00:00:30")
    Write-Host "ok: SIEMAgent installed and running"

    # 3. Enrollment reaches the server with the MSI properties.
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path (Join-Path $mockOut "enroll.json"))) {
        if ((Get-Date) -gt $deadline) { Fail "agent never enrolled" }
        Start-Sleep 2
    }
    $enroll = Get-Content (Join-Path $mockOut "enroll.json") | ConvertFrom-Json
    if ($enroll.enrollment_token -ne "ci-smoke-key-123") { Fail "enrolled with key '$($enroll.enrollment_token)'" }
    if ($enroll.name -ne "ci-windows") { Fail "enrolled with name '$($enroll.name)'" }
    Write-Host "ok: enrolled as $($enroll.name) ($($enroll.hostname)), version $($enroll.version)"

    $audit = auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" | Out-String
    if ($audit -notmatch "Success and Failure") { Fail "ENABLE_AUDITING=1 didn't enable logon auditing: $audit" }
    Write-Host "ok: logon auditing enabled"

    # 4. A new Application event is shipped as an EventID=... line. The subscription
    #    only sees future events, so keep writing until one arrives.
    $marker = "siem-smoke-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $deadline = (Get-Date).AddSeconds(120)
    $line = $null
    while (-not $line) {
        if ((Get-Date) -gt $deadline) { Fail "event '$marker' never reached the server" }
        eventcreate /T INFORMATION /ID 999 /L APPLICATION /SO SIEMSmoke /D $marker | Out-Null
        Start-Sleep 5
        if (Test-Path (Join-Path $mockOut "logs.jsonl")) {
            $line = Get-Content (Join-Path $mockOut "logs.jsonl") | ConvertFrom-Json |
                Where-Object { $_.raw_message -like "*$marker*" } | Select-Object -First 1
        }
    }
    if ($line.log_type -ne "windows_application") { Fail "log_type '$($line.log_type)'" }
    if ($line.raw_message -notmatch '^EventID=999 Channel="Application" Provider="SIEMSmoke"') {
        Fail "unexpected line format: $($line.raw_message)"
    }
    Write-Host "ok: event shipped: $($line.raw_message)"

    # 5. Uninstall removes the service but keeps the config (and its token).
    $code = Invoke-Msiexec @("/x", "`"$Msi`"") "uninstall.log"
    if ($code -ne 0) { Fail "msiexec /x exited $code" }
    if (Get-Service SIEMAgent -ErrorAction SilentlyContinue) { Fail "service still present after uninstall" }
    if (-not (Test-Path (Join-Path $dataDir "config.yaml"))) { Fail "config removed on uninstall" }
    Write-Host "ok: uninstalled; config kept in $dataDir"
    Write-Host "SMOKE TEST PASSED"
}
finally {
    Stop-Process -Id $mock.Id -Force -ErrorAction SilentlyContinue
    if ($caCert) {  # don't leave the throwaway test CA trusted on the machine
        $st = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine'); $st.Open('ReadWrite'); $st.Remove($caCert); $st.Close()
    }
}
