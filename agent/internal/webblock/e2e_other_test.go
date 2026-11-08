//go:build !linux && !windows

package webblock

import (
	"crypto/tls"
	"testing"
)

func e2eSkipUnlessPrivileged(t *testing.T) {
	t.Skip("web protection end-to-end is Linux and Windows only")
}
func e2eTLSConfig(t *testing.T) *tls.Config { return &tls.Config{} }
func e2eAssertTrustGone(t *testing.T)       {}
