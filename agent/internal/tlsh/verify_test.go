package tlsh

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// TestVerifyStdin checks Sum against digests published with real files:
// with TLSH_STDIN=1, stdin carries frames of a JSON line
// {"sha256":..., "tlsh":..., "n":<bytes>} followed by n bytes of content
// (ml/bench/tlsh_frames.py streams them from benchmark samples, decrypted
// in memory).
func TestVerifyStdin(t *testing.T) {
	if os.Getenv("TLSH_STDIN") != "1" {
		t.Skip("set TLSH_STDIN=1 and stream frames on stdin")
	}
	r := bufio.NewReader(os.Stdin)
	match, total := 0, 0
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			SHA  string `json:"sha256"`
			TLSH string `json:"tlsh"`
			N    int    `json:"n"`
		}
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, f.N)
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
		total++
		h, err := Sum(data)
		got := ""
		if err == nil {
			got = h.String()
		}
		// published forms: "T1" + 70 hex digits, the 70 digits alone (older
		// digests), or cut to 68 digits (URLhaus drops the last byte)
		g, p := norm(got), norm(f.TLSH)
		if g != "" && (g == p || (len(p) == 68 && strings.HasPrefix(g, p))) {
			match++
		} else {
			t.Errorf("%s: got %q, published %q", f.SHA, got, f.TLSH)
		}
	}
	t.Logf("%d of %d digests equal to the published ones", match, total)
	if total == 0 {
		t.Fatal("no frames")
	}
}

func norm(s string) string {
	return strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(s, "T1"), "t1"))
}
