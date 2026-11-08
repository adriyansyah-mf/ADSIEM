//go:build !linux && !windows

package webblock

func defaultHostsPath() string { return "/etc/hosts" }

func flushDNSCache() error { return nil }
