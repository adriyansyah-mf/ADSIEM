//go:build linux

package webblock

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

func e2eSkipUnlessPrivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("web protection end-to-end needs root (hosts file and trust store)")
	}
}

// e2eTLSConfig trusts the system pool, read after Apply so it contains the
// CA update-ca-certificates just installed.
func e2eTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("system cert pool: %v", err)
	}
	return &tls.Config{RootCAs: pool}
}

func e2eAssertTrustGone(t *testing.T) {
	t.Helper()
	for _, p := range []string{"/usr/local/share/ca-certificates/adsiem-webblock.crt", rhelAnchor} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("trust anchor %s still present: %v", p, err)
		}
	}
}
