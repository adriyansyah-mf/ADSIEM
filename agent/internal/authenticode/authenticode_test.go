package authenticode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tlv(class, tag int, compound bool, content ...[]byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: bytes.Join(content, nil)})
	if err != nil {
		panic(err)
	}
	return b
}

func seq(c ...[]byte) []byte { return tlv(asn1.ClassUniversal, asn1.TagSequence, true, c...) }
func set(c ...[]byte) []byte { return tlv(asn1.ClassUniversal, asn1.TagSet, true, c...) }

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// certs makes a CA and a code-signing certificate it issued.
func certs(t *testing.T, cn, org string) (ca, leaf *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Code Signing CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(4242),
		Subject:   pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	return ca, leaf
}

// signedData is a PKCS#7 ContentInfo whose SignerInfo names signer; certs
// holds every certificate (the CA first, as real signatures often do).
func signedData(signer *x509.Certificate, all ...*x509.Certificate) []byte {
	var raw [][]byte
	for _, c := range all {
		raw = append(raw, c.Raw)
	}
	sid := seq(signer.RawIssuer, mustMarshal(signer.SerialNumber))
	alg := seq(mustMarshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}))
	signerInfo := seq(mustMarshal(1), sid, alg, alg, tlv(asn1.ClassUniversal, asn1.TagOctetString, false, []byte("sig")))
	sd := seq(
		mustMarshal(1),
		set(alg),
		seq(mustMarshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4})), // SPC_INDIRECT_DATA
		tlv(asn1.ClassContextSpecific, 0, true, raw...),
		set(signerInfo),
	)
	return seq(mustMarshal(oidSignedData), tlv(asn1.ClassContextSpecific, 0, true, sd))
}

// pe is a minimal PE32 (or PE32+) file with cert as its attribute
// certificate table (nil: no security directory entry).
func pe(cert []byte, plus bool) []byte {
	const lfanew = 64
	optSize := 224
	magic := uint16(0x10b)
	dirs := 96
	if plus {
		optSize, magic, dirs = 240, 0x20b, 112
	}
	b := make([]byte, lfanew+24+optSize)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3C:], lfanew)
	copy(b[lfanew:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[lfanew+4:], 0x14c)
	binary.LittleEndian.PutUint16(b[lfanew+20:], uint16(optSize))
	opt := lfanew + 24
	binary.LittleEndian.PutUint16(b[opt:], magic)
	if cert != nil {
		win := make([]byte, 8, 8+len(cert))
		binary.LittleEndian.PutUint32(win[0:], uint32(8+len(cert)))
		binary.LittleEndian.PutUint16(win[4:], 0x0200)
		binary.LittleEndian.PutUint16(win[6:], 0x0002)
		win = append(win, cert...)
		binary.LittleEndian.PutUint32(b[opt+dirs+32:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[opt+dirs+36:], uint32(len(win)))
		b = append(b, win...)
	}
	return b
}

func parse(b []byte) (Signer, error) { return Parse(bytes.NewReader(b), int64(len(b))) }

func TestParseFindsTheSigningCertificate(t *testing.T) {
	ca, leaf := certs(t, "nordvpn s.a.", "nordvpn s.a.")
	for _, plus := range []bool{false, true} {
		s, err := parse(pe(signedData(leaf, ca, leaf), plus))
		if err != nil {
			t.Fatalf("plus=%v: %v", plus, err)
		}
		if s.Publisher != "nordvpn s.a." || s.Organization != "nordvpn s.a." || s.Issuer != "Test Code Signing CA" {
			t.Fatalf("plus=%v: %+v", plus, s)
		}
	}
}

func TestReadFile(t *testing.T) {
	ca, leaf := certs(t, "Proton AG", "Proton AG")
	p := filepath.Join(t.TempDir(), "setup.exe")
	os.WriteFile(p, pe(signedData(leaf, ca, leaf), true), 0o644)
	if s, err := ReadFile(p); err != nil || s.Publisher != "Proton AG" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestUnsignedAndNotPE(t *testing.T) {
	if _, err := parse(pe(nil, false)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("no security directory: %v", err)
	}
	if _, err := parse([]byte("\x7fELF not a windows program at all, just padding to sixty-four bytes")); !errors.Is(err, errNotPE) {
		t.Fatalf("ELF: %v", err)
	}
}

func TestBrokenSignaturesAreErrorsNotPanics(t *testing.T) {
	ca, leaf := certs(t, "X", "X")
	good := signedData(leaf, ca, leaf)
	other, _ := certs(t, "Someone Else", "Else")
	cases := map[string][]byte{
		"garbage":           []byte("not asn1 at all"),
		"truncated":         good[:len(good)/2],
		"signer not inside": signedData(leaf, ca, other),
		"empty":             {},
	}
	for name, sig := range cases {
		if _, err := parse(pe(sig, false)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// out-of-range directory
	b := pe(good, false)
	binary.LittleEndian.PutUint32(b[64+24+96+32:], 1<<30)
	if _, err := parse(b); err == nil {
		t.Error("directory past the end: want an error")
	}
}

func TestRandomBytesDoNotPanic(t *testing.T) {
	ca, leaf := certs(t, "X", "X")
	base := pe(signedData(leaf, ca, leaf), false)
	buf := make([]byte, len(base))
	for i := 0; i < 2000; i++ {
		copy(buf, base)
		for j := 0; j < 8; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(buf))))
			v, _ := rand.Int(rand.Reader, big.NewInt(256))
			buf[n.Int64()] = byte(v.Int64())
		}
		_, _ = parse(buf)
	}
}
