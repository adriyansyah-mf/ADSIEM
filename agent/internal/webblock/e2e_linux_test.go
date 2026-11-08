//go:build linux

package webblock

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
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
	for _, p := range []string{debianAnchor, suseAnchor, rhelAnchor} {
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

// e2eRequireRedirect fails loudly when the runner has neither nft nor
// iptables: without one the agent binds 127.84.0.1:80/443 directly (only when
// free), which is not what this test checks.
func e2eRequireRedirect(t *testing.T) {
	t.Helper()
	r := detectRedirect()
	if r == nil {
		t.Fatal("neither nft nor iptables is usable on this runner; the Linux block page needs one of them for its 127.84.0.1:80/443 redirect (install nftables or iptables)")
	}
	t.Logf("block page redirect backend: %T", r)
}

// e2eAssertWildcardBindable: the page server must not hold 80/443 on any
// address, so 0.0.0.0:80 and :443 bind (then close).
func e2eAssertWildcardBindable(t *testing.T) {
	t.Helper()
	for _, a := range []string{"0.0.0.0:80", "0.0.0.0:443"} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("a local service could not bind %s while web protection is active: %v", a, err)
		}
		ln.Close()
	}
}

// e2eAssertRedirectGone: neither the nft table nor the iptables chain is left.
func e2eAssertRedirectGone(t *testing.T) {
	t.Helper()
	if p, err := redirectLookPath("nft"); err == nil {
		if out, err := cmdRun(p, "", "list", "table", "ip", nftTable); err == nil {
			t.Fatalf("nft table %s still present:\n%s", nftTable, out)
		}
	}
	if p, err := redirectLookPath("iptables"); err == nil {
		if (iptRedirect{path: p}).chainExists() {
			t.Fatalf("iptables nat chain %s still present", iptChain)
		}
	}
}
