//go:build linux

package config

func defaultStateDir() (string, error) { return "/var/lib/siem-agent", nil }
