//go:build windows

package winsensor

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// SysmonInstalled reports whether Sysmon's service or driver is registered
// (Sysmon64, Sysmon or SysmonDrv): with it the ETW sensor would report the
// same processes and connections a second time.
func SysmonInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	for _, name := range []string{"Sysmon64", "Sysmon", "SysmonDrv"} {
		s, err := m.OpenService(name)
		if err == nil {
			s.Close()
			return true
		}
		if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return true // present but not openable: assume it runs
		}
	}
	return false
}
