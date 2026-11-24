package ransomguard

// Safe Mode: ransomware sets safeboot and reboots, because in Safe Mode
// most security software does not start. A service listed under
// HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal and \Network
// (default value "Service") does.
//
// The installer writes those keys when asked (install.ps1 -SafeMode, MSI
// SAFE_MODE=1), never the agent: a program adding itself to SafeBoot is how
// AsyncRAT persists, and Microsoft Defender kills and removes an unsigned
// agent that does it (Behavior:Win32/Asyncrat.A!sms). The agent only reads
// them, and removes them when it uninstalls its service.

const safeBootKey = `SYSTEM\CurrentControlSet\Control\SafeBoot\`

var safeBootModes = []string{"Minimal", "Network"}

// bootStore reads and deletes keys under HKLM (their default value).
type bootStore interface {
	get(key string) (string, bool, error)
	del(key string) error
}

// safeModeRegistered: the service starts in both Safe Mode variants.
func safeModeRegistered(s bootStore, service string) (bool, error) {
	for _, mode := range safeBootModes {
		v, ok, err := s.get(safeBootKey + mode + `\` + service)
		if err != nil || !ok || v != "Service" {
			return false, err
		}
	}
	return true, nil
}

// SafeModeRegistered tells whether the installer registered the agent's
// Windows service for Safe Mode (always false elsewhere).
func SafeModeRegistered(service string) (bool, error) {
	if platformBootStore == nil {
		return false, nil
	}
	return safeModeRegistered(platformBootStore, service)
}

// removeSafeMode deletes the service's Safe Mode registration (uninstall);
// keys already gone are fine.
func removeSafeMode(s bootStore, service string) error {
	for _, mode := range safeBootModes {
		if err := s.del(safeBootKey + mode + `\` + service); err != nil {
			return err
		}
	}
	return nil
}

// UnregisterSafeMode removes the agent service's Safe Mode registration
// (the uninstall path); nothing to do elsewhere.
func UnregisterSafeMode(service string) error {
	if platformBootStore == nil {
		return nil
	}
	return removeSafeMode(platformBootStore, service)
}
