//go:build windows

package webblock

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"golang.org/x/sys/windows"
)

func e2eSkipUnlessPrivileged(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("web protection end-to-end needs an elevated process (hosts file and machine ROOT store)")
	}
}

// e2eTLSConfig leaves RootCAs nil: on Windows Go verifies with the platform
// verifier, which reads the machine ROOT store.
func e2eTLSConfig(t *testing.T) *tls.Config { return &tls.Config{} }

func e2eAssertTrustGone(t *testing.T, _ []byte) {
	t.Helper()
	found := false
	if err := forEachOurs(func(c *x509.Certificate) bool { found = true; return false }); err != nil {
		t.Fatalf("enumerate ROOT store: %v", err)
	}
	if found {
		t.Fatal("an ADSIEM Web Protection certificate is still in the ROOT store")
	}
}
