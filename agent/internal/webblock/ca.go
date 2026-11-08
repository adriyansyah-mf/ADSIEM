package webblock

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	CAKeyFile  = "webblock-ca.key"
	CACertFile = "webblock-ca.crt"

	// caSubjectPrefix identifies every certificate this package installs.
	caSubjectPrefix = "ADSIEM Web Protection"

	caValidity     = 10 * 365 * 24 * time.Hour
	caRenewWindow  = 30 * 24 * time.Hour
	leafValidity   = 7 * 24 * time.Hour
	leafRefresh    = 24 * time.Hour
	leafCacheLimit = 1024
)

// CA is the per-endpoint certificate authority. Its private key never leaves
// the endpoint. It is installed as a root, so it is only ever used to sign
// leaves for hosts the caller allows (SetAllowed). No Name Constraints are set
// because the allowed set changes at runtime (documented risk).
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte

	mu      sync.Mutex
	allowed func(host string) bool
	cache   map[string]*list.Element
	lru     *list.List
}

type leafEntry struct {
	host string
	cert *tls.Certificate
	exp  time.Time
}

func newCA(cert *x509.Certificate, der []byte, key *ecdsa.PrivateKey) *CA {
	return &CA{Cert: cert, DER: der, Key: key, cache: map[string]*list.Element{}, lru: list.New()}
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func generateCA(hostname string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caSubjectPrefix + " (" + hostname + ")", Organization: []string{"ADSIEM"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, der, key), nil
}

// LoadOrCreateCA loads the CA from dir, regenerating it when the files are
// missing, corrupt, mismatched or expire within 30 days.
func LoadOrCreateCA(dir, hostname string) (*CA, bool, error) {
	if ca, err := loadCA(dir); err == nil {
		return ca, false, nil
	}
	ca, err := generateCA(hostname)
	if err != nil {
		return nil, false, err
	}
	if err := ca.save(dir); err != nil {
		return nil, false, err
	}
	return ca, true, nil
}

func loadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || cb.Type != "CERTIFICATE" || kb == nil {
		return nil, errors.New("webblock: CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("webblock: CA key does not match certificate")
	}
	if !cert.IsCA || !strings.HasPrefix(cert.Subject.CommonName, caSubjectPrefix) {
		return nil, errors.New("webblock: not an ADSIEM CA")
	}
	if time.Now().Add(caRenewWindow).After(cert.NotAfter) {
		return nil, errors.New("webblock: CA expiring")
	}
	// Re-tighten permissions in case they were loosened.
	if err := protectKeyFile(filepath.Join(dir, CAKeyFile)); err != nil {
		return nil, err
	}
	return newCA(cert, cb.Bytes, key), nil
}

func (c *CA) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	// Key first: a cert without a key is regenerated on the next load.
	if err := writeFileAtomic(filepath.Join(dir, CAKeyFile), keyPEM, true); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, CACertFile), c.PEM(), false)
}

// PEM returns the CA certificate in PEM form.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
}

// writeFileAtomic writes through a same-directory temp file created 0600, so
// a secret is never readable by others, even briefly, then renames it.
func writeFileAtomic(path string, data []byte, secret bool) error {
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if secret {
		if err := protectKeyFile(tmp); err != nil {
			return fail(err)
		}
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if !secret {
		os.Chmod(tmp, 0o644)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if secret {
		return protectKeyFile(path)
	}
	return nil
}

// Fingerprint is the lowercase hex SHA-256 of the DER certificate.
func (c *CA) Fingerprint() string { return fingerprintOf(c.DER) }

// SetAllowed sets the host filter consulted on every request, cache hits
// included, so a change takes effect immediately.
func (c *CA) SetAllowed(allowed func(host string) bool) {
	c.mu.Lock()
	c.allowed = allowed
	c.mu.Unlock()
}

// GetCertificate returns a leaf for the SNI, minting it when the host is
// allowed. It is safe for concurrent use.
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("webblock: no client hello")
	}
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, " /\\@:*") {
		return nil, errors.New("webblock: missing or invalid SNI")
	}
	c.mu.Lock()
	allowed := c.allowed
	c.mu.Unlock()
	if allowed == nil || !allowed(host) {
		return nil, fmt.Errorf("webblock: %s is not a listed host", host)
	}
	now := time.Now()
	c.mu.Lock()
	if el, ok := c.cache[host]; ok {
		e := el.Value.(*leafEntry)
		if now.Add(leafRefresh).Before(e.exp) {
			c.lru.MoveToFront(el)
			c.mu.Unlock()
			return e.cert, nil
		}
		c.lru.Remove(el)
		delete(c.cache, host)
	}
	c.mu.Unlock()

	cert, exp, err := c.mint(host, now)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.cache[host]; ok { // lost a race: keep the first
		c.lru.MoveToFront(el)
		return el.Value.(*leafEntry).cert, nil
	}
	c.cache[host] = c.lru.PushFront(&leafEntry{host: host, cert: cert, exp: exp})
	for c.lru.Len() > leafCacheLimit {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.cache, old.Value.(*leafEntry).host)
	}
	return cert, nil
}

func (c *CA) mint(host string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	exp := now.Add(leafValidity)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              exp,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, exp, nil
}

// Authority manages the CA lifecycle on the endpoint.
type Authority interface {
	Ensure(hostname string) (fingerprint string, err error)
	Remove() error
	Installed() bool
}

// TrustStore implements Authority with the operating system trust store.
type TrustStore struct {
	Dir string // state dir holding the CA files
}

// Ensure loads or creates the CA and installs it when new or missing.
func (t *TrustStore) Ensure(hostname string) (string, error) {
	ca, created, err := LoadOrCreateCA(t.Dir, hostname)
	if err != nil {
		return "", err
	}
	fp := ca.Fingerprint()
	if created || !trustInstalled(fp) {
		if err := removeTrust(fp); err != nil {
			return "", err
		}
		if err := installTrust(ca.DER, fp); err != nil {
			return "", err
		}
	}
	return fp, nil
}

// Installed reports whether the current CA is in the system trust store.
func (t *TrustStore) Installed() bool {
	ca, err := loadCA(t.Dir)
	if err != nil {
		return false
	}
	return trustInstalled(ca.Fingerprint())
}

// Remove drops the CA from the trust store and deletes its files.
func (t *TrustStore) Remove() error {
	err := removeTrust("")
	for _, n := range []string{CAKeyFile, CACertFile} {
		if rerr := os.Remove(filepath.Join(t.Dir, n)); rerr != nil && !os.IsNotExist(rerr) && err == nil {
			err = rerr
		}
	}
	return err
}
