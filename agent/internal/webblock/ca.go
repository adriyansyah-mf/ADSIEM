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
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	CAKeyFile  = "webblock-ca.key"
	CACertFile = "webblock-ca.crt"
	// CADirName is the protected directory under the state dir holding the CA.
	CADirName = "webblock"

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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// errRegenerate marks a CA on disk that must be replaced (corrupt, mismatched,
// wrong parameters, expiring). Other load errors (EACCES, EIO) are returned.
var errRegenerate = errors.New("webblock: CA must be regenerated")

func caDir(stateDir string) string { return filepath.Join(stateDir, CADirName) }

// LoadOrCreateCA loads the CA from stateDir/webblock, regenerating it when the
// files are missing, corrupt, mismatched, lack the server-auth restriction or
// expire within 30 days. Other errors are returned without regenerating.
func LoadOrCreateCA(stateDir, hostname string) (*CA, bool, error) {
	dir := caDir(stateDir)
	ca, err := loadCA(dir)
	if err == nil {
		return ca, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errRegenerate) {
		return nil, false, err
	}
	ca, err = generateCA(hostname)
	if err != nil {
		return nil, false, err
	}
	if err := ca.save(dir); err != nil {
		return nil, false, err
	}
	return ca, true, nil
}

func regen(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errRegenerate}, a...)...)
}

func loadCA(dir string) (*CA, error) {
	if _, err := os.Lstat(dir); err != nil {
		return nil, err
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
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
		return nil, regen("CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, regen("%v", err)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, regen("%v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, regen("key does not match certificate")
	}
	if !cert.IsCA || !cert.MaxPathLenZero || !strings.HasPrefix(cert.Subject.CommonName, caSubjectPrefix) {
		return nil, regen("not an ADSIEM CA")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, regen("CA lacks the server-auth restriction")
	}
	if time.Now().Add(caRenewWindow).After(cert.NotAfter) {
		return nil, regen("CA expiring")
	}
	return newCA(cert, cb.Bytes, key), nil
}

func (c *CA) save(dir string) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	// Key first: a cert without a key is regenerated on the next load.
	if err := writeSecretFile(dir, CAKeyFile, keyPEM); err != nil {
		return err
	}
	return writeSecretFile(dir, CACertFile, c.PEM())
}

// PEM returns the CA certificate in PEM form.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
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
	host, ok := normalizeSNI(hello.ServerName)
	if !ok {
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

// normalizeSNI lowercases, trims one trailing dot and requires a strict LDH
// hostname: labels of 1-63 characters, at least one dot, 253 bytes at most.
func normalizeSNI(sni string) (string, bool) {
	host := strings.ToLower(sni)
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", false
			}
		}
	}
	return host, true
}

// Trust store operations, replaced in tests.
var (
	doInstall   = installTrust
	doRemove    = removeTrust
	doInstalled = trustInstalled
)

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
	if created || !doInstalled(fp) {
		if err := doRemove(fp); err != nil {
			return "", err
		}
		if err := doInstall(ca.DER, fp); err != nil {
			return "", err
		}
	}
	return fp, nil
}

// Installed reports whether the current CA is in the system trust store.
func (t *TrustStore) Installed() bool {
	ca, err := loadCA(caDir(t.Dir))
	if err != nil {
		return false
	}
	return doInstalled(ca.Fingerprint())
}

// Remove drops the CA from the trust store and deletes its files.
func (t *TrustStore) Remove() error {
	err := doRemove("")
	dir := caDir(t.Dir)
	for _, n := range []string{CAKeyFile, CACertFile} {
		if rerr := os.Remove(filepath.Join(dir, n)); rerr != nil && !os.IsNotExist(rerr) && err == nil {
			err = rerr
		}
	}
	os.Remove(dir)
	return err
}
