// Package authenticode reads who signed a Windows program: the publisher
// named in the Authenticode signature embedded in a PE file (its security
// directory), without verifying it. The prevention engine matches signer
// rules against it, and App Control turns a matched file into a WDAC
// publisher rule (ConfigCI derives the certificate chain itself).
//
// Not verifying is deliberate: a signer rule only ever blocks, so a forged
// "signature" that names a blocked publisher is blocked too, and stripping
// the signature leaves an unsigned file for the path and hash rules.
// Catalog-signed files (Windows' own binaries) carry no embedded signature
// and report ErrUnsigned. Pure Go: it runs, and is tested, on any OS.
package authenticode

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

// Signer is the publisher of a signed program.
type Signer struct {
	Publisher    string // the signing certificate's subject common name (WDAC CertPublisher)
	Organization string // its subject organization, when set
	Issuer       string // the issuing CA's common name
}

// ErrUnsigned: the file has no embedded Authenticode signature.
var ErrUnsigned = errors.New("authenticode: no embedded signature")

// maxSignature bounds the security directory read (real ones are a few to
// a few hundred KB; a dual-signed driver stays well under this).
const maxSignature = 4 << 20

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	errNotPE      = errors.New("authenticode: not a PE file")
)

// ReadFile returns the signer of the PE file at path.
func ReadFile(path string) (Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return Signer{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Signer{}, err
	}
	return Parse(f, st.Size())
}

// Parse returns the signer of the PE file in r (size bytes long).
func Parse(r io.ReaderAt, size int64) (Signer, error) {
	off, n, err := securityDirectory(r, size)
	if err != nil {
		return Signer{}, err
	}
	blob := make([]byte, n)
	if _, err := r.ReadAt(blob, off); err != nil {
		return Signer{}, fmt.Errorf("authenticode: read signature: %w", err)
	}
	// WIN_CERTIFICATE: dwLength, wRevision, wCertificateType, bCertificate[]
	if len(blob) < 8 {
		return Signer{}, ErrUnsigned
	}
	length := binary.LittleEndian.Uint32(blob[0:4])
	certType := binary.LittleEndian.Uint16(blob[6:8])
	if certType != 0x0002 { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
		return Signer{}, ErrUnsigned
	}
	if int(length) > len(blob) || length < 8 {
		return Signer{}, errors.New("authenticode: bad certificate length")
	}
	return signerOf(blob[8:length])
}

// securityDirectory locates the attribute certificate table: data
// directory 4, whose VirtualAddress is a file offset.
func securityDirectory(r io.ReaderAt, size int64) (int64, int64, error) {
	var dos [64]byte
	if size < 64 {
		return 0, 0, errNotPE
	}
	if _, err := r.ReadAt(dos[:], 0); err != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return 0, 0, errNotPE
	}
	peOff := int64(binary.LittleEndian.Uint32(dos[0x3C:]))
	if peOff <= 0 || peOff > size-24 {
		return 0, 0, errNotPE
	}
	var hdr [24]byte // signature + COFF header
	if _, err := r.ReadAt(hdr[:], peOff); err != nil || !bytes.Equal(hdr[:4], []byte("PE\x00\x00")) {
		return 0, 0, errNotPE
	}
	optSize := int64(binary.LittleEndian.Uint16(hdr[20:22]))
	opt := peOff + 24
	var magic [2]byte
	if _, err := r.ReadAt(magic[:], opt); err != nil {
		return 0, 0, errNotPE
	}
	var dirs int64
	switch binary.LittleEndian.Uint16(magic[:]) {
	case 0x10b: // PE32
		dirs = 96
	case 0x20b: // PE32+
		dirs = 112
	default:
		return 0, 0, errNotPE
	}
	const security = 4
	entry := dirs + security*8
	if entry+8 > optSize {
		return 0, 0, ErrUnsigned // no security directory in this header
	}
	var dd [8]byte
	if _, err := r.ReadAt(dd[:], opt+entry); err != nil {
		return 0, 0, errNotPE
	}
	off := int64(binary.LittleEndian.Uint32(dd[0:4]))
	n := int64(binary.LittleEndian.Uint32(dd[4:8]))
	if off == 0 || n == 0 {
		return 0, 0, ErrUnsigned
	}
	if n > maxSignature || off < 0 || off+n > size {
		return 0, 0, errors.New("authenticode: security directory out of bounds")
	}
	return off, n, nil
}

// children returns the DER elements inside a constructed value.
func children(content []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(content) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(content, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		content = rest
	}
	return out, nil
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// signerOf finds, in a PKCS#7 SignedData ContentInfo, the certificate the
// first SignerInfo names (issuer and serial number).
func signerOf(der []byte) (Signer, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return Signer{}, fmt.Errorf("authenticode: content info: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return Signer{}, errors.New("authenticode: not signed data")
	}
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return Signer{}, fmt.Errorf("authenticode: signed data: %w", err)
	}
	fields, err := children(sd.Bytes)
	if err != nil {
		return Signer{}, fmt.Errorf("authenticode: signed data fields: %w", err)
	}
	// version, digestAlgorithms, contentInfo, [0] certificates, [1] crls, signerInfos
	var certs []*x509.Certificate
	var signerInfos *asn1.RawValue
	for i := range fields {
		f := &fields[i]
		switch {
		case f.Class == asn1.ClassContextSpecific && f.Tag == 0:
			elems, err := children(f.Bytes)
			if err != nil {
				return Signer{}, fmt.Errorf("authenticode: certificates: %w", err)
			}
			for _, e := range elems {
				if c, err := x509.ParseCertificate(e.FullBytes); err == nil {
					certs = append(certs, c)
				}
			}
		case f.Class == asn1.ClassUniversal && f.Tag == asn1.TagSet && i > 1:
			signerInfos = f // the last SET; digestAlgorithms is the SET at index 1
		}
	}
	if signerInfos == nil || len(certs) == 0 {
		return Signer{}, errors.New("authenticode: no signer or certificates")
	}
	infos, err := children(signerInfos.Bytes)
	if err != nil || len(infos) == 0 {
		return Signer{}, errors.New("authenticode: no signer info")
	}
	si, err := children(infos[0].Bytes)
	if err != nil || len(si) < 2 {
		return Signer{}, errors.New("authenticode: bad signer info")
	}
	var id issuerAndSerial
	if _, err := asn1.Unmarshal(si[1].FullBytes, &id); err != nil {
		return Signer{}, fmt.Errorf("authenticode: signer id: %w", err)
	}
	for _, c := range certs {
		if c.SerialNumber != nil && c.SerialNumber.Cmp(id.Serial) == 0 && bytes.Equal(c.RawIssuer, id.Issuer.FullBytes) {
			s := Signer{Publisher: c.Subject.CommonName, Issuer: c.Issuer.CommonName}
			if len(c.Subject.Organization) > 0 {
				s.Organization = c.Subject.Organization[0]
			}
			if s.Publisher == "" {
				return Signer{}, errors.New("authenticode: signing certificate has no common name")
			}
			return s, nil
		}
	}
	return Signer{}, errors.New("authenticode: signing certificate not in the signature")
}
