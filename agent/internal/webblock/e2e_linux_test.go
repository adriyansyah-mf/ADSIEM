//go:build linux

package webblock

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

func e2eAssertTrustGone(t *testing.T, caPEM []byte) {
	t.Helper()
	for _, p := range []string{"/usr/local/share/ca-certificates/adsiem-webblock.crt", rhelAnchor} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("trust anchor %s still present: %v", p, err)
		}
	}
	if bundle, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		if block, _ := pem.Decode(caPEM); block != nil {
			b64 := base64.StdEncoding.EncodeToString(block.Bytes)
			// PEM bodies are wrapped at 64 columns; compare the first line.
			if bytes.Contains(bundle, []byte(b64[:64])) {
				t.Fatal("the CA is still in /etc/ssl/certs/ca-certificates.crt")
			}
		}
	}
}
