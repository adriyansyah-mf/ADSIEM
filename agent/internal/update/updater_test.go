package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

var pkgBody = []byte("pretend this is a .deb")

func offer(t *testing.T, priv ed25519.PrivateKey, edit func(*Manifest)) *Offer {
	t.Helper()
	sum := sha256.Sum256(pkgBody)
	m := Manifest{Version: "2.0.0", OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "deb",
		File: "siem-agent_2.0.0_amd64.deb", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(pkgBody))}
	if edit != nil {
		edit(&m)
	}
	s, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &Offer{Version: "2.0.0", Revision: 1, URL: "/pkg", Signed: s}
}

type harness struct {
	u         *Updater
	installed chan string
	body      []byte
	installEr error
}

func newHarness(t *testing.T, dir, version string, pub ed25519.PublicKey) *harness {
	h := &harness{installed: make(chan string, 4), body: pkgBody}
	fetch := func(ctx context.Context, path string, w io.Writer) error {
		_, err := w.Write(h.body)
		return err
	}
	install := func(ctx context.Context, kind, pkg, log string) error {
		raw, _ := os.ReadFile(pkg)
		h.installed <- string(raw)
		if h.installEr != nil {
			_ = os.WriteFile(log, []byte("dpkg: error processing archive"), 0o600)
		}
		return h.installEr
	}
	h.u = New(dir, version, []ed25519.PublicKey{pub}, "deb", nil, fetch, install)
	return h
}

func waitState(t *testing.T, u *Updater, want string) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := u.Status(); s.State == want {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state %+v, want %s", u.Status(), want)
	return Status{}
}

func TestVerifyRejectsTamperingAndUnknownKeys(t *testing.T) {
	pub, priv := keypair(t)
	other, _ := keypair(t)
	o := offer(t, priv, nil)
	if _, err := Verify(o.Signed, []ed25519.PublicKey{pub}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(o.Signed, []ed25519.PublicKey{other}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("other key: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(o.Signed.Manifest)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["sha256"] = strings.Repeat("0", 64) // a server swapping the binary
	raw, _ = json.Marshal(m)
	tampered := o.Signed
	tampered.Manifest = base64.StdEncoding.EncodeToString(raw)
	if _, err := Verify(tampered, []ed25519.PublicKey{pub}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered manifest: %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	pub, _ := keypair(t)
	b := base64.StdEncoding.EncodeToString(pub)
	keys, err := ParseKeys(b + ", " + b)
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := ParseKeys("bm90LWEta2V5"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestOfferInstallsVerifiedPackage(t *testing.T) {
	pub, priv := keypair(t)
	h := newHarness(t, t.TempDir(), "1.0.0", pub)
	h.u.Offer(offer(t, priv, nil))
	if got := <-h.installed; got != string(pkgBody) {
		t.Fatalf("installed %q", got)
	}
	if s := h.u.Status(); s.State != "installing" || s.Target != "2.0.0" || s.Attempts != 1 {
		t.Fatalf("%+v", s)
	}
	h.u.Offer(offer(t, priv, nil)) // busy: one update at a time
	select {
	case <-h.installed:
		t.Fatal("second install while the first runs")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRefusesWhatTheSignatureDoesNotCover(t *testing.T) {
	pub, priv := keypair(t)
	cases := map[string]func(*harness) *Offer{
		"other platform": func(h *harness) *Offer { return offer(t, priv, func(m *Manifest) { m.Arch = "s390x" }) },
		"other format":   func(h *harness) *Offer { return offer(t, priv, func(m *Manifest) { m.Format = "msi" }) },
		"other version": func(h *harness) *Offer {
			o := offer(t, priv, nil)
			o.Version = "3.0.0" // the server names a version the manifest does not
			return o
		},
		"binary swapped": func(h *harness) *Offer {
			h.body = []byte("pretend this is a .deb!") // same length+1: over the signed size
			return offer(t, priv, nil)
		},
		"same size, other bytes": func(h *harness) *Offer {
			h.body = []byte("pretend this is a .DEB")
			return offer(t, priv, nil)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, t.TempDir(), "1.0.0", pub)
			h.u.Offer(mk(h))
			s := waitState(t, h.u, "failed")
			select {
			case <-h.installed:
				t.Fatal("installer ran")
			default:
			}
			if s.Error == "" {
				t.Fatal("no error reported")
			}
		})
	}
}

func TestOutcomeAfterRestart(t *testing.T) {
	pub, priv := keypair(t)
	dir := t.TempDir()
	h := newHarness(t, dir, "1.0.0", pub)
	h.u.Offer(offer(t, priv, nil))
	<-h.installed
	waitState(t, h.u, "installing")

	// the installer replaced the agent: the new process reports success
	if s := newHarness(t, dir, "2.0.0", pub).u.Status(); s.State != "updated" || s.Error != "" {
		t.Fatalf("new version: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(dir, "update", "pkg")); !os.IsNotExist(err) {
		t.Fatal("downloaded package left behind")
	}

	dir = t.TempDir()
	h = newHarness(t, dir, "1.0.0", pub)
	h.u.Offer(offer(t, priv, nil))
	<-h.installed
	_ = os.WriteFile(filepath.Join(dir, "update", "install.log"), []byte("dpkg: dependency problems"), 0o600)
	// the installer failed and the old version came back
	s := newHarness(t, dir, "1.0.0", pub).u.Status()
	if s.State != "failed" || !strings.Contains(s.Error, "still runs 1.0.0") || !strings.Contains(s.Error, "dependency problems") {
		t.Fatalf("old version back: %+v", s)
	}
}

func TestRetriesWithBackoffThenStops(t *testing.T) {
	pub, priv := keypair(t)
	h := newHarness(t, t.TempDir(), "1.0.0", pub)
	h.installEr = errors.New("exit status 1")
	clock := time.Now()
	h.u.now = func() time.Time { return clock }
	for i := 1; i <= MaxAttempts; i++ {
		h.u.Offer(offer(t, priv, nil))
		<-h.installed
		s := waitState(t, h.u, "failed")
		if s.Attempts != i || !strings.Contains(s.Error, "error processing archive") {
			t.Fatalf("attempt %d: %+v", i, s)
		}
		h.u.Offer(offer(t, priv, nil)) // inside the backoff: nothing
		select {
		case <-h.installed:
			t.Fatal("retried inside the backoff")
		case <-time.After(20 * time.Millisecond):
		}
		clock = clock.Add(retryAfter(i))
	}
	h.u.Offer(offer(t, priv, nil))
	select {
	case <-h.installed:
		t.Fatal("attempted past MaxAttempts")
	case <-time.After(20 * time.Millisecond):
	}
	// an operator retry is a new revision: attempts start over
	o := offer(t, priv, nil)
	o.Revision = 2
	h.u.Offer(o)
	<-h.installed
	if s := waitState(t, h.u, "failed"); s.Attempts != 1 || s.Revision != 2 {
		t.Fatalf("after retry: %+v", s)
	}
}

func TestUnsupportedWithoutKeyOrInstaller(t *testing.T) {
	u := New(t.TempDir(), "1.0.0", nil, "deb", nil, nil, nil)
	if s := u.Status(); s.State != "unsupported" || !strings.Contains(s.Error, "trusted update key") {
		t.Fatalf("%+v", s)
	}
	pub, priv := keypair(t)
	u = New(t.TempDir(), "1.0.0", []ed25519.PublicKey{pub}, "", errors.New("agent not installed from the deb or rpm package"), nil, nil)
	u.Offer(offer(t, priv, nil)) // must not touch nil fetch/install
	if s := u.Status(); s.State != "unsupported" || s.Kind != "" {
		t.Fatalf("%+v", s)
	}
}

// A fresh MSI install starts the service before the product is registered:
// detection is retried until it succeeds, then updates work.
func TestDetectionIsRetriedUntilTheInstallIsRegistered(t *testing.T) {
	pub, priv := keypair(t)
	h := newHarness(t, t.TempDir(), "1.0.0", pub)
	clock := time.Now()
	h.u = New(t.TempDir(), "1.0.0", []ed25519.PublicKey{pub}, "", errors.New("agent not installed from the MSI"),
		h.u.fetch, h.u.install)
	h.u.now = func() time.Time { return clock }
	registered := false
	h.u.Redetect(func() (string, error) {
		if !registered {
			return "", errors.New("agent not installed from the MSI")
		}
		return "deb", nil
	})
	if s := h.u.Status(); s.State != "unsupported" {
		t.Fatalf("%+v", s)
	}
	registered = true
	if s := h.u.Status(); s.State != "unsupported" {
		t.Fatalf("detected again inside the 30 s interval: %+v", s)
	}
	clock = clock.Add(redetectEvery)
	if s := h.u.Status(); s.State != "idle" || s.Kind != "deb" {
		t.Fatalf("after registration: %+v", s)
	}
	h.u.Offer(offer(t, priv, nil))
	<-h.installed
}

func TestSameVersionIsNotReinstalled(t *testing.T) {
	pub, priv := keypair(t)
	h := newHarness(t, t.TempDir(), "2.0.0", pub)
	h.u.Offer(offer(t, priv, nil))
	if s := h.u.Status(); s.State != "idle" {
		t.Fatalf("%+v", s)
	}
}
