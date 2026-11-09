//go:build !windows

package ransomguard

// No Safe Mode outside Windows.
var platformBootStore bootStore
