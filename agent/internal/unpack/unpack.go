// Package unpack opens the containers malware is delivered in, so the file
// engines (hashes, YARA, static ML) see what is inside and not only the
// wrapper: ZIP (and the formats built on it: docx, xlsx, jar, apk), ISO 9660
// disk images, gzip and tar, Windows shortcuts (LNK: their target and
// arguments, as text), and HTML smuggling (large base64 blobs in a page that
// decode to a program or an archive).
//
// Everything happens in memory and is bounded (Limits): depth, entry count,
// entry size, total size, and the compression ratio, against archive bombs.
// Encrypted entries are not opened; they are reported in Result.Notes.
// 7z and RAR are not supported.
package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// Sep separates a container's path from the path inside it in Item.Path:
// "C:\Users\bob\Downloads\invoice.zip|invoice.exe". Windows forbids "|" in
// file names, so the outer path is unambiguous there.
const Sep = "|"

// Outer is the file on disk a path names: the container's path for an
// "outer|inner" path (what to quarantine), else path itself.
func Outer(path string) string {
	if i := strings.Index(path, Sep); i > 0 {
		if _, err := os.Lstat(path[:i]); err == nil {
			return path[:i]
		}
	}
	return path
}

// Limits bound the work done on one file.
type Limits struct {
	Depth      int   // containers inside containers
	Entries    int   // items returned
	EntrySize  int64 // bytes of one item
	TotalSize  int64 // bytes of all items
	MaxRatio   int64 // uncompressed / compressed, per entry
	HTMLMax    int   // HTML pages larger than this are not searched for blobs
	MinBlobLen int   // base64 runs shorter than this are not decoded
}

// DefaultLimits are what the agent uses.
var DefaultLimits = Limits{Depth: 3, Entries: 1000, EntrySize: 64 << 20, TotalSize: 256 << 20, MaxRatio: 200,
	HTMLMax: 20 << 20, MinBlobLen: 1024}

// Item is one file found inside a container.
type Item struct {
	Path string // relative: "dir/a.exe", or "outer.zip|inner.exe" for nested ones
	Kind string // what it came out of: zip, iso, gzip, tar, lnk, html
	Data []byte
}

// Result of opening one file.
type Result struct {
	Items []Item
	Notes []string // entries left out and why (encrypted, too large, limits)
}

type state struct {
	lim   Limits
	total int64
	res   Result
}

// Open returns what is inside data (nothing when it is not a container).
func Open(data []byte, lim Limits) Result {
	s := &state{lim: lim}
	s.open("", data, 0)
	return s.res
}

func (s *state) note(format string, args ...any) {
	if len(s.res.Notes) < 100 {
		s.res.Notes = append(s.res.Notes, fmt.Sprintf(format, args...))
	}
}

// add keeps one item and opens it in turn when it is a container.
func (s *state) add(prefix, name, kind string, data []byte, depth int) bool {
	if len(s.res.Items) >= s.lim.Entries {
		s.note("more than %d entries: the rest not opened", s.lim.Entries)
		return false
	}
	if s.total+int64(len(data)) > s.lim.TotalSize {
		s.note("more than %d bytes inside: the rest not opened", s.lim.TotalSize)
		return false
	}
	s.total += int64(len(data))
	path := name
	if prefix != "" {
		path = prefix + Sep + name
	}
	s.res.Items = append(s.res.Items, Item{Path: path, Kind: kind, Data: data})
	if depth+1 < s.lim.Depth {
		s.open(path, data, depth+1)
	}
	return true
}

// Kind names the container format of data, or "".
func Kind(data []byte) string {
	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("PK\x03\x04")):
		return "zip"
	case len(data) >= 0x8006 && bytes.Equal(data[0x8001:0x8006], []byte("CD001")):
		return "iso"
	case len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8:
		return "gzip"
	case len(data) >= 263 && bytes.Equal(data[257:262], []byte("ustar")):
		return "tar"
	case isLNK(data):
		return "lnk"
	case looksHTML(data):
		return "html"
	}
	return ""
}

func (s *state) open(prefix string, data []byte, depth int) {
	switch Kind(data) {
	case "zip":
		s.zip(prefix, data, depth)
	case "iso":
		s.iso(prefix, data, depth)
	case "gzip":
		s.gzip(prefix, data, depth)
	case "tar":
		s.tar(prefix, data, depth)
	case "lnk":
		if text := lnkText(data); text != "" {
			s.add(prefix, "lnk-target.txt", "lnk", []byte(text), depth)
		}
	case "html":
		if len(data) <= s.lim.HTMLMax {
			s.html(prefix, data, depth)
		}
	}
}

func (s *state) readLimited(r io.Reader, name string, compressed int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r, s.lim.EntrySize+1))
	if err != nil {
		s.note("%s: %v", name, err)
		return nil, false
	}
	if int64(len(b)) > s.lim.EntrySize {
		s.note("%s: larger than %d bytes", name, s.lim.EntrySize)
		return nil, false
	}
	if compressed > 0 && int64(len(b)) > 1<<20 && int64(len(b))/compressed > s.lim.MaxRatio {
		s.note("%s: compression ratio over %d (archive bomb?)", name, s.lim.MaxRatio)
		return nil, false
	}
	return b, true
}

func (s *state) zip(prefix string, data []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.note("zip: %v", err)
		return
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&0x1 != 0 {
			s.note("%s: encrypted", f.Name)
			continue
		}
		if int64(f.UncompressedSize64) > s.lim.EntrySize {
			s.note("%s: larger than %d bytes", f.Name, s.lim.EntrySize)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.note("%s: %v", f.Name, err)
			continue
		}
		b, ok := s.readLimited(rc, f.Name, int64(f.CompressedSize64)+1)
		rc.Close()
		if ok && len(b) > 0 && !s.add(prefix, f.Name, "zip", b, depth) {
			return
		}
	}
}

func (s *state) gzip(prefix string, data []byte, depth int) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		s.note("gzip: %v", err)
		return
	}
	defer zr.Close()
	name := zr.Name
	if name == "" {
		name = "gzip-content"
	}
	if b, ok := s.readLimited(zr, name, int64(len(data))); ok {
		s.add(prefix, name, "gzip", b, depth)
	}
}

func (s *state) tar(prefix string, data []byte, depth int) {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err != nil {
			if err != io.EOF {
				s.note("tar: %v", err)
			}
			return
		}
		if h.Typeflag != tar.TypeReg || h.Size == 0 {
			continue
		}
		if h.Size > s.lim.EntrySize {
			s.note("%s: larger than %d bytes", h.Name, s.lim.EntrySize)
			continue
		}
		if b, ok := s.readLimited(tr, h.Name, 0); ok && !s.add(prefix, h.Name, "tar", b, depth) {
			return
		}
	}
}

func looksHTML(data []byte) bool {
	head := strings.ToLower(string(data[:min(len(data), 4096)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html") ||
		strings.Contains(head, "<script") || strings.Contains(head, "<svg")
}
