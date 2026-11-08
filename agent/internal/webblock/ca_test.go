package webblock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
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

func TestCAParameters(t *testing.T) {
	ca, _ := newTestCA(t)
	c := ca.Cert
	if !c.IsCA || !c.MaxPathLenZero || c.MaxPathLen != 0 {
		t.Fatalf("basic constraints: %+v", c)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("no CertSign")
	}
	if c.Subject.CommonName != "ADSIEM Web Protection (host1)" || c.Subject.Organization[0] != "ADSIEM" {
		t.Fatalf("subject %v", c.Subject)
	}
	if d := c.NotAfter.Sub(time.Now()); d < 9*365*24*time.Hour || d > 10*365*24*time.Hour+time.Hour {
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
	os.WriteFile(filepath.Join(dir, CAKeyFile), []byte("garbage"), 0o600)
	ca2, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created || ca2.Fingerprint() == ca.Fingerprint() {
		t.Fatalf("corrupt: %v created=%v", err, created)
	}
	// Mismatch: key from another CA.
	otherDir := t.TempDir()
	LoadOrCreateCA(otherDir, "x")
	b, _ := os.ReadFile(filepath.Join(otherDir, CAKeyFile))
	os.WriteFile(filepath.Join(dir, CAKeyFile), b, 0o600)
	_, created, err = LoadOrCreateCA(dir, "host1")
	if err != nil || !created {
		t.Fatalf("mismatch: %v created=%v", err, created)
	}
}

func TestCARegeneratesWhenExpiring(t *testing.T) {
	ca, dir := newTestCA(t)
	// Make the stored cert expire in 10 days.
	tpl := *ca.Cert
	tpl.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	der, err := x509.CreateCertificate(crand.Reader, &tpl, &tpl, &ca.Key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	short := newCA(ca.Cert, der, ca.Key)
	if err := short.save(dir); err != nil {
		t.Fatal(err)
	}
	_, created, err := LoadOrCreateCA(dir, "host1")
	if err != nil || !created {
		t.Fatalf("expiring: %v created=%v", err, created)
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
	}
	for _, sni := range []string{"", "other.example", "1.2.3.4", "a b"} {
		if _, err := tlsFor(t, ca, sni); err == nil {
			t.Fatalf("expected error for %q", sni)
		}
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
		tlsFor(t, ca, "h"+string(rune('a'+i%26))+time.Duration(i).String()+".example")
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

func TestKeyFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DACL based")
	}
	_, dir := newTestCA(t)
	st, err := os.Stat(filepath.Join(dir, CAKeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, CAKeyFile+".tmp")); err == nil {
		t.Fatal("temp file left behind")
	}
}
