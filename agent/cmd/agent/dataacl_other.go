//go:build !windows

package main

// protectDataDir: on Linux siem-agent-configure's chmod 0600 holds.
func protectDataDir(string) error { return nil }
