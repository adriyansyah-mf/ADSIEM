package webblock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}
	return ca, dir
}

func keyPath(stateDir string) string  { return filepath.Join(caDir(stateDir), CAKeyFile) }
func certPath(stateDir string) string { return filepath.Join(caDir(stateDir), CACertFile) }

func TestCAParameters(t *testing.T) {
	ca, _ := newTestCA(t)
	c := ca.Cert
	if !c.IsCA || !c.MaxPathLenZero || c.MaxPathLen != 0 {
		t.Fatalf("basic constraints: %+v", c)
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("key usage %v", c.KeyUsage)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("eku %v", c.ExtKeyUsage)
	}
	if c.Subject.CommonName != "ADSIEM Web Protection (host1)" || c.Subject.Organization[0] != "ADSIEM" {
		t.Fatalf("subject %v", c.Subject)
	}
	want := 10*365*24*time.Hour + time.Hour
	if d := c.NotAfter.Sub(c.NotBefore); d < want-time.Minute || d > want+time.Minute {
		t.Fatalf("validity %v", d)
	}
	if pk, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Fatal("not P-256")
	}
	if len(ca.Fingerprint()) != 64 {
		t.Fatal("fingerprint")
	}
}

func TestCAReload(t *testing.T) {
	ca, dir := newTestCA(t)
	ca2, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || created || ca2.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: %v created=%v", err, created)
	}
}

func TestCARegeneratesOnCorruptOrMismatch(t *testing.T) {
	ca, dir := newTestCA(t)
	os.WriteFile(keyPath(dir), []byte("garbage"), 0o600)
	ca2, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created || ca2.Fingerprint() == ca.Fingerprint() {
		t.Fatalf("corrupt: %v created=%v", err, created)
	}
	otherDir := t.TempDir()
	LoadOrCreateCA(otherDir, "x")
	b, _ := os.ReadFile(keyPath(otherDir))
	os.WriteFile(keyPath(dir), b, 0o600)
	_, created, err = LoadOrCreateCA(dir, "host1")
	if err != nil || !created {
		t.Fatalf("mismatch: %v created=%v", err, created)
	}
}

// rewriteCert replaces the stored certificate with one built from a modified
// template signed by the same key.
func rewriteCert(t *testing.T, ca *CA, dir string, mod func(*x509.Certificate)) {
	t.Helper()
	tpl := *ca.Cert
	mod(&tpl)
	der, err := x509.CreateCertificate(crand.Reader, &tpl, &tpl, &ca.Key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if err := newCA(cert, der, ca.Key).save(caDir(dir)); err != nil {
		t.Fatal(err)
	}
}

func TestCARegeneratesWhenExpiring(t *testing.T) {
	ca, dir := newTestCA(t)
	rewriteCert(t, ca, dir, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(10 * 24 * time.Hour) })
	_, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created {
		t.Fatalf("expiring: %v created=%v", err, created)
	}
}

func TestCARegeneratesWithoutServerAuthEKU(t *testing.T) {
	ca, dir := newTestCA(t)
	rewriteCert(t, ca, dir, func(c *x509.Certificate) { c.ExtKeyUsage = nil })
	// Sanity: with the EKU the same cert is kept.
	ca2, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created || ca2.Fingerprint() == ca.Fingerprint() {
		t.Fatalf("no-EKU CA must be regenerated: %v created=%v", err, created)
	}
	if len(ca2.Cert.ExtKeyUsage) != 1 {
		t.Fatal("regenerated CA lacks EKU")
	}
	_, created, _ = LoadOrCreateCA(dir, "host1")
	if created {
		t.Fatal("CA with EKU must be kept")
	}
}

func TestCAUnreadableKeyIsNotRegenerated(t *testing.T) {
	if os.Geteuid() == 0 || os.PathSeparator == '\\' {
		t.Skip("needs a non-root unix user")
	}
	ca, dir := newTestCA(t)
	if err := os.Chmod(keyPath(dir), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(keyPath(dir), 0o600)
	if _, created, err := LoadOrCreateCA(dir, "host1"); err == nil || created {
		t.Fatalf("expected error without regeneration: %v created=%v", err, created)
	}
	os.Chmod(keyPath(dir), 0o600)
	again, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || created || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("CA was replaced: %v", err)
	}
}

func tlsFor(t *testing.T, ca *CA, sni string) (*tls.Certificate, error) {
	t.Helper()
	return ca.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
}

func TestLeafVerifiesAndAllowList(t *testing.T) {
	ca, _ := newTestCA(t)
	ca.SetAllowed(func(h string) bool { return h == "evil.example" || h == "www.evil.example" })
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	for _, sni := range []string{"evil.example", "www.evil.example", "EVIL.example."} {
		leaf, err := tlsFor(t, ca, sni)
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		c, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		name := c.DNSNames[0]
		if _, err := c.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
		if c.NotAfter.Sub(c.NotBefore) > 7*24*time.Hour+time.Hour+time.Minute || c.IsCA {
			t.Fatalf("leaf shape %v..%v", c.NotBefore, c.NotAfter)
		}
		if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || c.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Fatalf("leaf usages %v %v", c.ExtKeyUsage, c.KeyUsage)
		}
	}
	for _, sni := range []string{"", "other.example", "1.2.3.4"} {
		if _, err := tlsFor(t, ca, sni); err == nil {
			t.Fatalf("expected error for %q", sni)
		}
	}
}

func TestStrictSNI(t *testing.T) {
	ca, _ := newTestCA(t)
	called := false
	ca.SetAllowed(func(string) bool { called = true; return true })
	bad := []string{"a..", "evil..example", "evil.example\x00", "ev\til.example", "a b.example",
		strings.Repeat("a", 64) + ".example", "localhost", ".example", "*.example", "a_b.example",
		"evil.example..", "é.example", strings.Repeat("a.", 130) + "com"}
	for _, sni := range bad {
		if _, err := tlsFor(t, ca, sni); err == nil {
			t.Fatalf("accepted %q", sni)
		}
	}
	if called {
		t.Fatal("allow() consulted for an invalid SNI")
	}
	if _, err := tlsFor(t, ca, strings.Repeat("a", 63)+".example"); err != nil {
		t.Fatalf("63-char label rejected: %v", err)
	}
}

func TestNoAllowFuncRefuses(t *testing.T) {
	ca, _ := newTestCA(t)
	if _, err := tlsFor(t, ca, "evil.example"); err == nil {
		t.Fatal("must refuse without SetAllowed")
	}
}

func TestLeafCachedAndAllowChangeApplies(t *testing.T) {
	ca, _ := newTestCA(t)
	ok := true
	ca.SetAllowed(func(string) bool { return ok })
	a, _ := tlsFor(t, ca, "evil.example")
	b, _ := tlsFor(t, ca, "evil.example")
	if a == nil || a != b {
		t.Fatal("second mint should return the cached leaf")
	}
	ok = false
	if _, err := tlsFor(t, ca, "evil.example"); err == nil {
		t.Fatal("cached leaf served after host was removed")
	}
}

func TestLeafRefreshedNearExpiryAndLRUBound(t *testing.T) {
	ca, _ := newTestCA(t)
	ca.SetAllowed(func(string) bool { return true })
	a, _ := tlsFor(t, ca, "evil.example")
	ca.mu.Lock()
	ca.cache["evil.example"].Value.(*leafEntry).exp = time.Now().Add(time.Hour)
	ca.mu.Unlock()
	b, _ := tlsFor(t, ca, "evil.example")
	if a == b {
		t.Fatal("leaf within 24h of expiry must be re-minted")
	}
	for i := 0; i < leafCacheLimit+20; i++ {
		name := fmt.Sprintf("h%d.example", i)
		if _, err := tlsFor(t, ca, name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if ca.lru.Len() > leafCacheLimit || len(ca.cache) != ca.lru.Len() {
		t.Fatalf("lru %d cache %d", ca.lru.Len(), len(ca.cache))
	}
}

func TestGetCertificateConcurrent(t *testing.T) {
	ca, _ := newTestCA(t)
	ca.SetAllowed(func(string) bool { return true })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if i == 0 {
					ca.SetAllowed(func(string) bool { return true })
				}
				if _, err := tlsFor(t, ca, "evil.example"); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestEnsureOrdering(t *testing.T) {
	oldI, oldR, oldS := doInstall, doRemove, doInstalled
	defer func() { doInstall, doRemove, doInstalled = oldI, oldR, oldS }()
	var calls []string
	installed := false
	doRemove = func(string) error { calls = append(calls, "remove"); installed = false; return nil }
	doInstall = func([]byte, string) error { calls = append(calls, "install"); installed = true; return nil }
	doInstalled = func(string) bool { return installed }

	ts := &TrustStore{Dir: t.TempDir()}
	fp, err := ts.Ensure("host1")
	if err != nil || len(fp) != 64 {
		t.Fatalf("ensure: %v", err)
	}
	if strings.Join(calls, ",") != "remove,install" {
		t.Fatalf("order %v", calls)
	}
	if !ts.Installed() {
		t.Fatal("Installed false")
	}
	calls = nil
	fp2, err := ts.Ensure("host1")
	if err != nil || fp2 != fp || len(calls) != 0 {
		t.Fatalf("unchanged CA reinstalled: %v %v", err, calls)
	}
	installed = false // removed behind our back: reinstall
	if _, err := ts.Ensure("host1"); err != nil || strings.Join(calls, ",") != "remove,install" {
		t.Fatalf("reinstall: %v %v", err, calls)
	}
	if err := ts.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath(ts.Dir)); err == nil {
		t.Fatal("key survived Remove")
	}
}
