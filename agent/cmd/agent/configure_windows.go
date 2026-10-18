//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/siem-platform/agent/internal/config"
)

// Same channels as packaging/windows/config.yaml.
func defaultLogSources() []config.LogSource {
	return []config.LogSource{
		{Path: "eventlog:Security", Type: "windows_security", Enabled: true},
		{Path: "eventlog:System", Type: "windows_system", Enabled: true},
		{Path: "eventlog:Application", Type: "windows_application", Enabled: true},
		{Path: "eventlog:Microsoft-Windows-Sysmon/Operational", Type: "windows_sysmon", Enabled: true},
		{Path: "eventlog:Microsoft-Windows-PowerShell/Operational", Type: "windows_powershell", Enabled: true},
	}
}

// restrictConfigAccess limits the data directory (config with the agent token,
// agent.log) to SYSTEM and Administrators.
func restrictConfigAccess(path string) error {
	dir := filepath.Dir(path)
	out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// enableAuditing turns on what the Windows decoders and rules read: logon,
// process creation (with command line), account and group management,
// scheduled tasks, and PowerShell script block logging.
func enableAuditing() error {
	for _, args := range [][]string{
		{"/set", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}", "/success:enable", "/failure:enable"}, // Logon
		{"/set", "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}", "/success:enable"},                    // Process Creation
		{"/set", "/subcategory:{0CCE9235-69AE-11D9-BED3-505054503030}", "/success:enable", "/failure:enable"}, // User Account Management
		{"/set", "/subcategory:{0CCE9237-69AE-11D9-BED3-505054503030}", "/success:enable"},                    // Security Group Management
		{"/set", "/subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}", "/success:enable"},                    // Other Object Access (tasks)
	} {
		if out, err := exec.Command("auditpol", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("auditpol %s: %v: %s", args[1], err, strings.TrimSpace(string(out)))
		}
	}
	for _, v := range []struct{ path, name string }{
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "ProcessCreationIncludeCmdLine_Enabled"},
		{`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging"},
	} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, v.path, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf(`HKLM\%s: %w`, v.path, err)
		}
		err = k.SetDWordValue(v.name, 1)
		k.Close()
		if err != nil {
			return fmt.Errorf(`HKLM\%s\%s: %w`, v.path, v.name, err)
		}
	}
	return nil
}
