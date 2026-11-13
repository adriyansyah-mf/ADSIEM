//go:build !windows

package firewall

// newPlatformIOC: WFP exists on Windows only.
func newPlatformIOC() IOCSetter { return nil }
