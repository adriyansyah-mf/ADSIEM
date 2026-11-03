// Package zipcrypto reads entries of zip files encrypted with the legacy
// PKWARE scheme ("ZipCrypto"), which archive/zip does not decrypt: the
// format MalwareBazaar and most sample exchanges use (password "infected").
// Entries are decrypted in memory; nothing is written to disk.
package zipcrypto

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// ErrAES: the entry uses WinZip AES (method 99), not ZipCrypto.
var ErrAES = errors.New("zip entry uses AES encryption, not ZipCrypto")

// ErrPassword: the password check byte or the CRC did not match.
var ErrPassword = errors.New("wrong password or corrupt entry")

type keys [3]uint32

func newKeys(password []byte) *keys {
	k := &keys{0x12345678, 0x23456789, 0x34567890}
	for _, b := range password {
		k.update(b)
	}
	return k
}

func (k *keys) update(b byte) {
	k[0] = crc32.IEEETable[byte(k[0])^b] ^ (k[0] >> 8)
	k[1] = (k[1]+(k[0]&0xff))*134775813 + 1
	k[2] = crc32.IEEETable[byte(k[2])^byte(k[1]>>24)] ^ (k[2] >> 8)
}

func (k *keys) decrypt(buf []byte) {
	for i, c := range buf {
		t := uint16(k[2] | 2)
		p := c ^ byte((t*(t^1))>>8)
		k.update(p)
		buf[i] = p
	}
}

// ReadFile returns the content of f, decrypting it with password when it is
// encrypted, and at most max bytes (larger entries are an error).
func ReadFile(f *zip.File, password []byte, max int64) ([]byte, error) {
	if int64(f.UncompressedSize64) > max {
		return nil, fmt.Errorf("%s: %d bytes, more than %d", f.Name, f.UncompressedSize64, max)
	}
	if f.Flags&0x1 == 0 { // not encrypted
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, max+1))
	}
	if f.Method == 99 {
		return nil, ErrAES
	}
	raw, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	enc, err := io.ReadAll(io.LimitReader(raw, int64(f.CompressedSize64)+1))
	if err != nil {
		return nil, err
	}
	if len(enc) < 12 {
		return nil, ErrPassword
	}
	k := newKeys(password)
	k.decrypt(enc)
	// the 12th header byte is the CRC's high byte, or the time's with a data descriptor
	check := byte(f.CRC32 >> 24)
	if f.Flags&0x8 != 0 {
		check = byte(f.ModifiedTime >> 8)
	}
	if enc[11] != check {
		return nil, ErrPassword
	}
	body := enc[12:]
	var out []byte
	switch f.Method {
	case zip.Store:
		out = body
	case zip.Deflate:
		fr := flate.NewReader(bytes.NewReader(body))
		out, err = io.ReadAll(io.LimitReader(fr, max+1))
		fr.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
	default:
		return nil, fmt.Errorf("%s: compression method %d not supported", f.Name, f.Method)
	}
	if int64(len(out)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", f.Name, max)
	}
	if crc32.ChecksumIEEE(out) != f.CRC32 {
		return nil, ErrPassword
	}
	return out, nil
}
