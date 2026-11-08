//go:build !linux && !windows

package webblock

import "errors"

func installTrust(der []byte, fingerprint string) error { return errors.ErrUnsupported }
func removeTrust(fingerprint string) error              { return errors.ErrUnsupported }
func trustInstalled(fingerprint string) bool            { return false }
func protectKeyFile(path string) error                  { return nil }
