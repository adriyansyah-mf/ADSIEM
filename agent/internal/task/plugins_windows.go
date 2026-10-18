//go:build windows

package task

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Windows implementations of the plugins that read /proc and /etc on Linux.
// Same plugin names, so the server's artifacts run unchanged; columns follow
// the Linux ones where an equivalent exists.
func init() {
	Plugins["pslist"] = func(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
		return emitPowerShell(ctx, psPslist, emit)
	}
	Plugins["netstat"] = func(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
		return emitPowerShell(ctx, psNetstat, emit)
	}
	Plugins["users"] = func(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
		return emitPowerShell(ctx, psUsers, emit)
	}
	Plugins["persistence"] = func(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
		return emitPowerShell(ctx, psPersistence, emit)
	}
	Plugins["dmesg"] = unsupported("dmesg has no Windows equivalent; collect System events with an eventlog:System log source")
	Plugins["open_files"] = unsupported("open_files is not available on Windows")
}

func unsupported(msg string) Plugin {
	return func(context.Context, map[string]any, func(map[string]any) error) error {
		return fmt.Errorf("%s", msg)
	}
}

// emitPowerShell runs a script whose output is a JSON array of objects (from
// ConvertTo-Json -InputObject @(...)) and emits each object as a row.
func emitPowerShell(ctx context.Context, script string, emit func(map[string]any) error) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; "+
			"[Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("powershell: %w", err)
	}
	out = bytes.TrimSpace(bytes.TrimPrefix(out, []byte("\xef\xbb\xbf")))
	if len(out) == 0 {
		return nil
	}
	if out[0] == '{' { // a single object rather than an array
		out = append(append([]byte("["), out...), ']')
	}
	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		return fmt.Errorf("powershell output: %w", err)
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

const psPslist = `
$users = @{}
Get-Process -IncludeUserName | ForEach-Object { $users[$_.Id] = $_.UserName }
$rows = Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{
    Pid = [int]$_.ProcessId; Ppid = [int]$_.ParentProcessId; Name = $_.Name
    Username = $users[[int]$_.ProcessId]; Exe = $_.ExecutablePath; CommandLine = $_.CommandLine
    Threads = [int]$_.ThreadCount; RssKb = [int64]([int64]$_.WorkingSetSize / 1024)
    StartTime = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { '' }
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3`

const psNetstat = `
$names = @{}
Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
$tcp = Get-NetTCPConnection | ForEach-Object {
  [pscustomobject]@{
    Proto = 'tcp'; LocalAddr = $_.LocalAddress; LocalPort = [int]$_.LocalPort
    RemoteAddr = $_.RemoteAddress; RemotePort = [int]$_.RemotePort
    State = $_.State.ToString().ToUpper(); Pid = [string]$_.OwningProcess; Process = $names[[int]$_.OwningProcess]
  }
}
$udp = Get-NetUDPEndpoint | ForEach-Object {
  [pscustomobject]@{
    Proto = 'udp'; LocalAddr = $_.LocalAddress; LocalPort = [int]$_.LocalPort
    RemoteAddr = ''; RemotePort = 0; State = 'UNCONN'
    Pid = [string]$_.OwningProcess; Process = $names[[int]$_.OwningProcess]
  }
}
ConvertTo-Json -InputObject @(@($tcp) + @($udp)) -Compress -Depth 3`

const psUsers = `
$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
$rows = Get-LocalUser | ForEach-Object {
  [pscustomobject]@{
    Username = $_.Name; Uid = $_.SID.Value; Enabled = [bool]$_.Enabled; Admin = ($admins -contains $_.SID.Value)
    Description = $_.Description
    LastLogon = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { '' }
    PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToUniversalTime().ToString('o') } else { '' }
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3`

// Common autostart locations (MITRE T1547.001, T1053.005, T1543.003, T1546.003).
const psPersistence = `
$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($cat, $path, $content, $mod) {
  $rows.Add([pscustomobject]@{ Category = $cat; Path = $path; Content = [string]$content; ModTime = $mod })
}
$runKeys = @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
$hives = @('Registry::HKEY_LOCAL_MACHINE') + @(Get-ChildItem Registry::HKEY_USERS |
  Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" })
foreach ($h in $hives) { foreach ($k in $runKeys) {
  $item = Get-ItemProperty -Path "$h\$k"
  if ($item) { $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
    ForEach-Object { Add-Row 'run_key' "$h\$k\$($_.Name)" $_.Value '' } }
} }
$startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
  @(Get-ChildItem 'C:\Users' -Directory | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
foreach ($d in $startup) { Get-ChildItem -Path $d -File | ForEach-Object {
  Add-Row 'startup_folder' $_.FullName '' $_.LastWriteTimeUtc.ToString('o') } }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $acts = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; '
  Add-Row 'scheduled_task' "$($_.TaskPath)$($_.TaskName)" $acts '' }
Get-CimInstance Win32_Service | Where-Object {
  $_.StartMode -eq 'Auto' -and $_.PathName -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\svchost\.exe' } |
  ForEach-Object { Add-Row 'service' $_.Name $_.PathName '' }
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
  $c = if ($_.CommandLineTemplate) { $_.CommandLineTemplate } elseif ($_.ScriptText) { $_.ScriptText } else { '' }
  Add-Row 'wmi_subscription' $_.Name $c '' }
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3`
