package unpack

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
)

// HTML smuggling: the page carries the payload as a base64 string and
// builds it in the browser (Blob + a download link, or atob into an
// iframe), so no executable crosses the proxy. Long base64 runs are decoded,
// and kept when the result is a program or a container.

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`)

// payloadMagic: what a smuggled blob is kept for.
func payloadMagic(b []byte) bool {
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z',
		len(b) >= 4 && bytes.Equal(b[:4], []byte("\x7fELF")),
		Kind(b) == "zip", Kind(b) == "iso", Kind(b) == "gzip", isLNK(b),
		len(b) >= 6 && bytes.Equal(b[:6], []byte("7z\xbc\xaf\x27\x1c")),
		len(b) >= 4 && bytes.Equal(b[:4], []byte("Rar!")),
		len(b) >= 8 && bytes.Equal(b[:8], []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")): // OLE: Office, MSI
		return true
	}
	return false
}

func (s *state) html(prefix string, data []byte, depth int) {
	n := 0
	for _, loc := range base64Run.FindAllIndex(data, 200) {
		run := data[loc[0]:loc[1]]
		if len(run) < s.lim.MinBlobLen {
			continue
		}
		p := padded(run)
		dec := make([]byte, base64.StdEncoding.DecodedLen(len(p)))
		m, err := base64.StdEncoding.Decode(dec, p)
		if err != nil || !payloadMagic(dec[:m]) {
			continue
		}
		n++
		if !s.add(prefix, fmt.Sprintf("html-blob-%d", n), "html", dec[:m], depth) {
			return
		}
	}
}

// padded completes a base64 run cut without its padding.
func padded(b []byte) []byte {
	if r := len(b) % 4; r != 0 {
		return append(append([]byte(nil), b...), bytes.Repeat([]byte("="), 4-r)...)
	}
	return b
}
