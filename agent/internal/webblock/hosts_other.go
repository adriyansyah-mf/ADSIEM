//go:build !linux && !windows

package webblock

import "os"

func defaultHostsPath() string { return "/etc/hosts" }

func replaceFile(tmp, dst string) error { return os.Rename(tmp, dst) }

func flushDNSCache() error { return nil }
