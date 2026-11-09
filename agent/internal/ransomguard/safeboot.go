package ransomguard

// Safe Mode: ransomware sets safeboot and reboots, because in Safe Mode
// most security software does not start. A service listed under
// HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal and \Network
// (default value "Service") does, so the agent registers itself there.

const safeBootKey = `SYSTEM\CurrentControlSet\Control\SafeBoot\`

// bootStore reads and writes the default value of a key under HKLM.
type bootStore interface {
	get(key string) (value string, ok bool, err error)
	set(key, value string) error
}

// ensureSafeMode registers service for Safe Mode (Minimal and Network);
// it returns the keys it changed (none when already registered).
func ensureSafeMode(s bootStore, service string) ([]string, error) {
	var changed []string
	for _, mode := range []string{"Minimal", "Network"} {
		key := safeBootKey + mode + `\` + service
		v, ok, err := s.get(key)
		if err != nil {
			return changed, err
		}
		if ok && v == "Service" {
			continue
		}
		if err := s.set(key, "Service"); err != nil {
			return changed, err
		}
		changed = append(changed, key)
	}
	return changed, nil
}

// RegisterSafeMode makes the agent's Windows service start in Safe Mode
// (idempotent); nothing to do elsewhere.
func RegisterSafeMode(service string) ([]string, error) {
	if platformBootStore == nil {
		return nil, nil
	}
	return ensureSafeMode(platformBootStore, service)
}
