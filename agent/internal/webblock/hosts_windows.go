//go:build windows

package webblock

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func defaultHostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// replaceFile renames tmp over dst, retrying while antivirus or another
// process holds the hosts file open.
func replaceFile(tmp, dst string) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.Rename(tmp, dst); err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		if i < 4 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return err
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNSCache() error {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return err
	}
	// Returns BOOL; zero means failure.
	if r, _, err := procDnsFlushResolverCache.Call(); r == 0 {
		return err
	}
	return nil
}
