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

// writeHosts rewrites the file in place so its ACL and attributes (hidden,
// system) survive. A read-only attribute is cleared for the write and the
// original attributes are restored afterwards, also on error.
func writeHosts(path string, data []byte, mode os.FileMode) (err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, aerr := windows.GetFileAttributes(p)
	if aerr == nil && attrs&windows.FILE_ATTRIBUTE_READONLY != 0 {
		if err := windows.SetFileAttributes(p, attrs&^windows.FILE_ATTRIBUTE_READONLY); err != nil {
			return err
		}
		defer func() {
			if rerr := windows.SetFileAttributes(p, attrs); rerr != nil && err == nil {
				err = rerr
			}
		}()
	}
	var f *os.File
	for i := 0; i < 5; i++ {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if i < 4 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
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
