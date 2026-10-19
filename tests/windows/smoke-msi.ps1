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
$env:MOCK_FLOW = "1"
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

    # 4b. The hygiene report (first one ~30 s after start) describes this host.
    $hygPath = Join-Path $mockOut "hygiene.json"
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Test-Path $hygPath)) {
        if ((Get-Date) -gt $deadline) { Fail "no hygiene report received" }
        Start-Sleep 5
    }
    $h = Get-Content $hygPath -Raw | ConvertFrom-Json
    if ($h.os_name -notlike "Windows*") { Fail "hygiene os_name '$($h.os_name)'" }
    if ($h.mem_total_mb -le 0 -or $h.cpu_count -le 0 -or $h.uptime_seconds -le 0) { Fail "hygiene memory/cpu/uptime missing" }
    if (-not ($h.disk_partitions | Where-Object { $_.mount -eq "C:" -and $_.total_mb -gt 0 })) { Fail "hygiene has no C: disk" }
    if (-not ($h.open_ports | Where-Object { $_.port -eq 135 })) { Fail "hygiene open_ports lacks 135 (RPC)" }
    if (@($h.users).Count -lt 1) { Fail "hygiene has no local users" }
    if (@($h.packages).Count -lt 1 -or ($h.packages | Where-Object { $_.source -ne "windows" })) { Fail "hygiene packages missing or wrong source" }
    if ($h.hygiene_score -lt 0 -or $h.hygiene_score -gt 100) { Fail "hygiene score $($h.hygiene_score)" }
    Write-Host ("ok: hygiene: {0} {1} (kernel {2}), {3} MB RAM, {4} ports, {5} users, {6} programs, score {7}, issues: {8}" -f
        $h.os_name, $h.os_version, $h.kernel, $h.mem_total_mb, @($h.open_ports).Count, @($h.users).Count,
        @($h.packages).Count, $h.hygiene_score, ((@($h.issues) | ForEach-Object { $_.message }) -join "; "))

    # 4c. Live response: a flow running every Windows plugin (Windows.* artifacts) returns rows.
    New-Item -ItemType File -Force -Path (Join-Path $mockOut "send_flow") | Out-Null
    $flowsPath = Join-Path $mockOut "flows.jsonl"
    $deadline = (Get-Date).AddSeconds(240)
    $updates = @()
    while ($true) {
        if (Test-Path $flowsPath) { $updates = @(Get-Content $flowsPath | ConvertFrom-Json) }
        if ($updates | Where-Object { $_.state -in @("finished", "error", "cancelled") }) { break }
        if ((Get-Date) -gt $deadline) { Fail "live-response flow didn't finish" }
        Start-Sleep 3
    }
    $final = $updates | Where-Object { $_.state -in @("finished", "error", "cancelled") } | Select-Object -First 1
    $errors = @($updates | ForEach-Object { $_.logs } | Where-Object { $_ -and $_.level -eq "error" })
    if ($final.state -ne "finished" -or $errors) {
        Fail ("flow ended '{0}' {1}; errors: {2}" -f $final.state, $final.error, (($errors | ForEach-Object { $_.message }) -join " | "))
    }
    $rowsBy = @{}
    foreach ($u in $updates) { if ($u.source -and $u.rows) { $rowsBy[$u.source] = @($rowsBy[$u.source]) + @($u.rows) } }
    foreach ($src in "Info", "Pslist", "Users", "Persistence", "Services", "Programs", "Netstat", "Events") {
        if (@($rowsBy[$src]).Count -lt 1) { Fail "live-response source $src returned no rows" }
    }
    $info = $rowsBy["Info"][0]
    if ($info.OSRelease -notlike "Windows*") { Fail "info OSRelease '$($info.OSRelease)'" }
    if (-not ($rowsBy["Pslist"] | Where-Object { $_.Name -eq "siem-agent.exe" })) { Fail "pslist lacks the agent itself" }
    if (-not ($rowsBy["Services"] | Where-Object { $_.Name -eq "SIEMAgent" })) { Fail "services lacks SIEMAgent" }
    $ev = $rowsBy["Events"] | Where-Object { $_.Data1 -like "siem-smoke-*" } | Select-Object -First 1
    if (-not $ev -or $ev.EventID -ne "999" -or $ev.Provider -ne "SIEMSmoke") { Fail "eventlog didn't return the smoke event" }
    Write-Host ("ok: live response: " + (($rowsBy.Keys | Sort-Object | ForEach-Object { "$_=$(@($rowsBy[$_]).Count)" }) -join ", ") +
        "; info: $($info.OSRelease) $($info.Kernel)")

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
