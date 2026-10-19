//go:build windows

package task

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/siem-platform/agent/internal/winevent"
)

// Windows-only plugins (Windows.* artifacts): host info from the registry,
// historical event log queries, services and installed programs.
func init() {
	Plugins["info"] = pluginInfoWindows
	Plugins["eventlog"] = pluginEventLog
	Plugins["services"] = func(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
		return emitPowerShell(ctx, psServices, emit)
	}
	Plugins["programs"] = pluginPrograms
}

func regStr(k registry.Key, path, name string) string {
	key, err := registry.OpenKey(k, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	v, _, _ := key.GetStringValue(name)
	return v
}

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func pluginInfoWindows(_ context.Context, _ map[string]any, emit func(map[string]any) error) error {
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	hostname, _ := os.Hostname()
	product := regStr(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regStr(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	if b, _ := strconv.Atoi(build); b >= 22000 && strings.Contains(product, "Windows 10") {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1) // ProductName still says 10
	}
	release := strings.TrimSpace(product + " " + regStr(registry.LOCAL_MACHINE, cv, "DisplayVersion"))
	ms, _, _ := procGetTickCount64.Call()
	return emit(map[string]any{
		"Hostname":  hostname,
		"OS":        runtime.GOOS,
		"OSRelease": release,
		"Kernel":    "10.0." + build,
		"Arch":      runtime.GOARCH,
		"UptimeSec": int(ms / 1000),
		"Domain":    regStr(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "Domain"),
	})
}

// pluginEventLog queries a channel's existing events (newest first): args
// channel, event_ids ("4624,4625"), hours (default 24, 0 = all), limit
// (default 1000), or a raw xpath. Rows carry the same fields the agent ships
// for live events (EventID, TimeCreated, ..., EventData).
func pluginEventLog(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	channel := argString(args, "channel", "")
	if channel == "" {
		return fmt.Errorf("eventlog: channel is required (e.g. Security)")
	}
	xpath, err := eventlogXPath(args)
	if err != nil {
		return err
	}
	limit := argInt(args, "limit", 1000)
	return winevent.Query(ctx, channel, xpath, limit, func(raw []byte) error {
		fields, ferr := winevent.Fields(raw)
		if ferr != nil {
			return nil
		}
		row := make(map[string]any, len(fields))
		for k, v := range fields {
			row[k] = v
		}
		if t, perr := time.Parse(time.RFC3339Nano, fields["TimeCreated"]); perr == nil {
			row["TimeCreated"] = t.UTC().Format(time.RFC3339)
		}
		return emit(row)
	})
}

const psServices = `
$rows = Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{
    Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode
    Account = $_.StartName; Pid = [int]$_.ProcessId; PathName = $_.PathName; Description = $_.Description
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3`

// pluginPrograms lists Add/Remove Programs: machine-wide (64- and 32-bit views)
// and per user (HKU\<SID>).
func pluginPrograms(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
	type root struct {
		key   registry.Key
		path  string
		scope string
	}
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	roots := []root{
		{registry.LOCAL_MACHINE, uninstall, "machine"},
		{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "machine (32-bit)"},
	}
	if users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := users.ReadSubKeyNames(-1)
		users.Close()
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				roots = append(roots, root{registry.USERS, sid + `\` + uninstall, "user " + sid})
			}
		}
	}
	var rows []map[string]any
	for _, r := range roots {
		k, err := registry.OpenKey(r.key, r.path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range subs {
			full := r.path + `\` + sub
			name := regStr(r.key, full, "DisplayName")
			if name == "" {
				continue
			}
			rows = append(rows, map[string]any{
				"Name":            name,
				"Version":         regStr(r.key, full, "DisplayVersion"),
				"Publisher":       regStr(r.key, full, "Publisher"),
				"InstallDate":     regStr(r.key, full, "InstallDate"),
				"InstallLocation": regStr(r.key, full, "InstallLocation"),
				"UninstallString": regStr(r.key, full, "UninstallString"),
				"Scope":           r.scope,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i]["Name"].(string)) < strings.ToLower(rows[j]["Name"].(string))
	})
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
