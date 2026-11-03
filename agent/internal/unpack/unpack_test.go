package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

var fakeExe = []byte("MZ fake program: not executable, only the magic matters\x00\x01\x02")

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, b := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(b)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func paths(r Result) map[string]string {
	m := map[string]string{}
	for _, it := range r.Items {
		m[it.Path] = it.Kind
	}
	return m
}

func TestZipNestedZip(t *testing.T) {
	inner := zipOf(t, map[string][]byte{"payload.exe": fakeExe})
	outer := zipOf(t, map[string][]byte{"invoice.zip": inner, "readme.txt": []byte("hi")})
	r := Open(outer, DefaultLimits)
	got := paths(r)
	for _, want := range []string{"invoice.zip", "readme.txt", "invoice.zip|payload.exe"} {
		if got[want] != "zip" {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, it := range r.Items {
		if it.Path == "invoice.zip|payload.exe" && !bytes.Equal(it.Data, fakeExe) {
			t.Error("payload content differs")
		}
	}
}

func TestEncryptedEntryIsANote(t *testing.T) {
	b, err := os.ReadFile("../zipcrypto/testdata/deflate.zip")
	if err != nil {
		t.Fatal(err)
	}
	r := Open(b, DefaultLimits)
	if len(r.Items) != 0 || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "encrypted") {
		t.Fatalf("items %v notes %v", paths(r), r.Notes)
	}
}

func TestGzipISO(t *testing.T) {
	b, err := os.ReadFile("testdata/small.iso.gz") // genisoimage: DOCS/INVOICE.EXE, README.TXT
	if err != nil {
		t.Fatal(err)
	}
	r := Open(b, DefaultLimits)
	got := paths(r)
	if got["small.iso"] != "gzip" || got["small.iso|DOCS/INVOICE.EXE"] != "iso" || got["small.iso|README.TXT"] != "iso" {
		t.Fatalf("items %v notes %v", got, r.Notes)
	}
	for _, it := range r.Items {
		if it.Path == "small.iso|DOCS/INVOICE.EXE" && !bytes.HasPrefix(it.Data, []byte("MZ fake program")) {
			t.Errorf("INVOICE.EXE = %q", it.Data)
		}
	}
}

func TestTarGz(t *testing.T) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "bin/miner", Mode: 0o755, Size: int64(len(fakeExe)), Typeflag: tar.TypeReg})
	tw.Write(fakeExe)
	tw.Close()
	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	gw.Write(tb.Bytes())
	gw.Close()
	got := paths(Open(gb.Bytes(), DefaultLimits))
	if got["gzip-content"] != "gzip" || got["gzip-content|bin/miner"] != "tar" {
		t.Fatalf("items %v", got)
	}
}

// lnkFile builds a shortcut with Unicode string data: relative path,
// working dir and arguments, as Explorer writes them.
func lnkFile(rel, workdir, args string) []byte {
	b := make([]byte, 0x4C)
	binary.LittleEndian.PutUint32(b, 0x4C)
	copy(b[4:], lnkCLSID)
	binary.LittleEndian.PutUint32(b[0x14:], lnkHasRelPath|lnkHasWorkDir|lnkHasArgs|lnkIsUnicode)
	for _, s := range []string{rel, workdir, args} {
		u := utf16.Encode([]rune(s))
		b = binary.LittleEndian.AppendUint16(b, uint16(len(u)))
		for _, c := range u {
			b = binary.LittleEndian.AppendUint16(b, c)
		}
	}
	return b
}

func TestLNKCommandLine(t *testing.T) {
	lnk := lnkFile(`..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows`,
		`-w hidden -enc SQBFAFgA`)
	r := Open(zipOf(t, map[string][]byte{"Invoice.pdf.lnk": lnk}), DefaultLimits)
	var text string
	for _, it := range r.Items {
		if it.Path == "Invoice.pdf.lnk|lnk-target.txt" {
			text = string(it.Data)
		}
	}
	for _, want := range []string{"relative_path: ..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		"working_dir: C:\\Windows", "arguments: -w hidden -enc SQBFAFgA"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %q (items %v)", want, text, paths(r))
		}
	}
	if lnkText(lnk[:0x50]) != "" {
		t.Error("a truncated shortcut gave text")
	}
}

func TestHTMLSmuggling(t *testing.T) {
	noise := make([]byte, 4000) // incompressible: the blob must pass MinBlobLen
	rand.New(rand.NewSource(1)).Read(noise)
	payload := zipOf(t, map[string][]byte{"setup.exe": append(append([]byte(nil), fakeExe...), noise...)})
	page := `<html><body><script>var d = "` + base64.StdEncoding.EncodeToString(payload) +
		`"; var b = new Blob([Uint8Array.from(atob(d), c => c.charCodeAt(0))]);</script></body></html>`
	got := paths(Open([]byte(page), DefaultLimits))
	if got["html-blob-1"] != "html" || got["html-blob-1|setup.exe"] != "zip" {
		t.Fatalf("items %v", got)
	}
	// base64 of plain text is not kept
	text := `<html><img src="data:image/png;base64,` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("abc"), 2000)) + `"></html>`
	if got := paths(Open([]byte(text), DefaultLimits)); len(got) != 0 {
		t.Fatalf("items %v", got)
	}
}

func TestLimits(t *testing.T) {
	bomb := zipOf(t, map[string][]byte{"zeros.bin": make([]byte, 20<<20)})
	r := Open(bomb, DefaultLimits)
	if len(r.Items) != 0 || len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "ratio") {
		t.Fatalf("bomb: items %v notes %v", paths(r), r.Notes)
	}
	many := map[string][]byte{}
	for i := 0; i < 30; i++ {
		many[strings.Repeat("a", i+1)+".txt"] = []byte("x")
	}
	lim := DefaultLimits
	lim.Entries = 10
	if r := Open(zipOf(t, many), lim); len(r.Items) != 10 {
		t.Fatalf("%d items, want 10", len(r.Items))
	}
	// depth: a zip in a zip in a zip, depth 2 opens two levels
	z := zipOf(t, map[string][]byte{"a.exe": fakeExe})
	z = zipOf(t, map[string][]byte{"l2.zip": z})
	z = zipOf(t, map[string][]byte{"l1.zip": z})
	lim = DefaultLimits
	lim.Depth = 2
	got := paths(Open(z, lim))
	if _, ok := got["l1.zip|l2.zip"]; !ok || len(got) != 2 {
		t.Fatalf("depth 2: %v", got)
	}
}

func TestOuter(t *testing.T) {
	p := t.TempDir() + "/mail.zip"
	os.WriteFile(p, []byte("x"), 0o644)
	for in, want := range map[string]string{
		p + Sep + "a.exe":          p,
		p:                          p,
		"/no/such.zip" + Sep + "a": "/no/such.zip" + Sep + "a",
	} {
		if got := Outer(in); got != want {
			t.Errorf("Outer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNotAContainer(t *testing.T) {
	for _, b := range [][]byte{fakeExe, []byte("#!/bin/sh\necho hi\n"), {}, []byte("PK")} {
		if r := Open(b, DefaultLimits); len(r.Items) != 0 {
			t.Errorf("%q: %v", b, paths(r))
		}
	}
}
