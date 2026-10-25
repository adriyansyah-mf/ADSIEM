package yara

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// benchRules is a mixed set shaped like public rule packs: literals
// with modifiers, hex with wildcards and jumps, regexes, module calls.
func benchRules(n int) string {
	var b strings.Builder
	b.WriteString("import \"pe\"\nimport \"math\"\n")
	for i := 0; i < n; i++ {
		switch i % 6 {
		case 0:
			fmt.Fprintf(&b, "rule t%d { strings: $a = \"malware_marker_%d\" $b = \"evil-%d.example\" nocase condition: any of them }\n", i, i, i)
		case 1:
			fmt.Fprintf(&b, "rule w%d { strings: $a = \"Software\\\\Run%d\" wide ascii condition: $a }\n", i, i)
		case 2:
			fmt.Fprintf(&b, "rule x%d { strings: $a = \"This program %d\" xor condition: $a }\n", i, i)
		case 3:
			fmt.Fprintf(&b, "rule h%d { strings: $a = { 4D 5A ?? 00 [4-16] %02X 45 ( 00 | 4C ) } condition: $a at 0 or #a > 2 }\n", i, i&0xff)
		case 4:
			fmt.Fprintf(&b, "rule r%d { strings: $a = /c2-%d\\.[a-z]{3,10}\\.(com|net)/ condition: $a }\n", i, i)
		case 5:
			fmt.Fprintf(&b, "rule p%d { condition: pe.is_pe and pe.number_of_sections > %d and math.entropy(0, 4096) > 7 }\n", i, i%8)
		}
	}
	return b.String()
}

func BenchmarkScan10MB(b *testing.B) {
	rules, err := Compile(benchRules(60))
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 10<<20)
	rand.New(rand.NewSource(1)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rules.Scan(context.Background(), data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanText10MB(b *testing.B) {
	rules, err := Compile(benchRules(60))
	if err != nil {
		b.Fatal(err)
	}
	words := []string{"the ", "c2 ", "evil ", "malware ", "program ", "This ", "com ", "\n", "Software ", "Run "}
	var sb strings.Builder
	r := rand.New(rand.NewSource(1))
	for sb.Len() < 10<<20 {
		sb.WriteString(words[r.Intn(len(words))])
	}
	data := []byte(sb.String())
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rules.Scan(context.Background(), data); err != nil {
			b.Fatal(err)
		}
	}
}
