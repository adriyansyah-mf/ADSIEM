// Package update installs agent packages the server offers, but only ones
// signed by a key this agent trusts: a compromised server can pick which
// signed release an agent runs, never what code is in it.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Product guards against a signature made with the same key for something
// that is not an agent package.
const Product = "siem-agent"

// Manifest describes one package file. Its exact JSON bytes are what is
// signed, and they travel base64-encoded so nothing re-serializes them.
type Manifest struct {
	Schema  int    `json:"schema"`
	Product string `json:"product"`
	Version string `json:"version"`
	OS      string `json:"os"`     // GOOS
	Arch    string `json:"arch"`   // GOARCH
	Format  string `json:"format"` // deb | rpm | msi
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Signed is the content of a package's .sig file, also sent in heartbeat offers.
type Signed struct {
	Manifest  string `json:"manifest"`  // base64 of the manifest JSON
	Signature string `json:"signature"` // base64 ed25519 signature over those bytes
	KeyID     string `json:"key_id"`
}

// KeyID names a public key in logs and .sig files: the first 8 bytes of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParseKeys reads base64 ed25519 public keys separated by commas or spaces.
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		raw, err := base64.StdEncoding.DecodeString(f)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("update key %q: not a base64 ed25519 public key", f)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// Sign makes the .sig content for m.
func Sign(m Manifest, priv ed25519.PrivateKey) (Signed, error) {
	m.Schema, m.Product = 1, Product
	raw, err := json.Marshal(m)
	if err != nil {
		return Signed{}, err
	}
	return Signed{
		Manifest:  base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)),
		KeyID:     KeyID(priv.Public().(ed25519.PublicKey)),
	}, nil
}

var ErrUntrusted = errors.New("package signature does not verify with any trusted update key")

// Verify checks s against keys and returns the manifest it signs.
func Verify(s Signed, keys []ed25519.PublicKey) (Manifest, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest encoding: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return Manifest{}, fmt.Errorf("signature encoding: %w", err)
	}
	ok := false
	for _, k := range keys {
		ok = ok || ed25519.Verify(k, raw, sig)
	}
	if !ok {
		return Manifest{}, ErrUntrusted
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != 1 || m.Product != Product {
		return Manifest{}, fmt.Errorf("manifest: schema %d product %q not supported", m.Schema, m.Product)
	}
	if len(m.SHA256) != 64 || m.Size <= 0 || m.Version == "" {
		return Manifest{}, errors.New("manifest: missing version, sha256 or size")
	}
	return m, nil
}
