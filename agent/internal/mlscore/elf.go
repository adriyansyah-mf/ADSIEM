package mlscore

import (
	"bytes"
	"debug/elf"
	"strings"
)

// ELF has no public labelled dataset like EMBER, so ELF files get a
// heuristic score from traits that are rare in packaged software and common
// in Linux malware (miners, botnets, droppers). Each trait adds weight; the
// score is capped below 1 and the reasons are reported with it.

type trait struct {
	weight float64
	reason string
}

var elfStrings = []struct {
	needle []byte
	t      trait
}{
	{[]byte("stratum+tcp://"), trait{0.45, "mining pool URL (stratum)"}},
	{[]byte("stratum+ssl://"), trait{0.45, "mining pool URL (stratum)"}},
	{[]byte("xmrig"), trait{0.35, "XMRig miner"}},
	{[]byte("cryptonight"), trait{0.3, "CryptoNight miner"}},
	{[]byte("/dev/tcp/"), trait{0.25, "bash reverse shell"}},
	{[]byte("/etc/ld.so.preload"), trait{0.3, "writes the LD preload file"}},
	{[]byte("LD_PRELOAD"), trait{0.1, "LD_PRELOAD"}},
	{[]byte("/proc/self/exe"), trait{0.05, "reads its own executable"}},
	{[]byte("chattr -i"), trait{0.2, "removes immutable flags"}},
	{[]byte("/etc/cron"), trait{0.1, "touches cron"}},
	{[]byte(".ssh/authorized_keys"), trait{0.2, "touches SSH authorized keys"}},
	{[]byte("iptables -F"), trait{0.2, "flushes the firewall"}},
	{[]byte("pkill -9"), trait{0.1, "kills other processes"}},
	{[]byte("kill -9 -1"), trait{0.1, "kills other processes"}},
	{[]byte("/bin/busybox"), trait{0.1, "busybox (IoT botnets)"}},
	{[]byte("Mozilla/5.0 (Windows NT"), trait{0.05, "browser user agent in a Linux binary"}},
}

// preloadTraits are left out for the dynamic loader, which has them all.
var preloadTraits = map[string]bool{"writes the LD preload file": true, "LD_PRELOAD": true, "reads its own executable": true}

// ScoreELF returns a heuristic score in [0, 0.99] and the reasons, or ok
// false when b is not an ELF file.
func ScoreELF(b []byte) (score float64, reasons []string, ok bool) {
	if len(b) < 64 || !bytes.Equal(b[:4], []byte("\x7fELF")) {
		return 0, nil, false
	}
	add := func(t trait) {
		score += t.weight
		reasons = append(reasons, t.reason)
	}
	if bytes.Contains(b, []byte("UPX!")) {
		add(trait{0.35, "packed with UPX"})
	}
	loader := false // the dynamic loader itself: it reads the preload file
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		add(trait{0.3, "malformed ELF headers"})
	} else {
		if len(f.Sections) == 0 {
			add(trait{0.25, "no section headers"})
		}
		highEntropy := false
		for _, s := range f.Sections {
			if s.Type == elf.SHT_NOBITS || s.Size < 4096 {
				continue
			}
			if data, err := s.Data(); err == nil && shannon(data) > 7.4 {
				highEntropy = true
			}
		}
		if highEntropy {
			add(trait{0.2, "section with packed / encrypted content"})
		}
		static, interp := true, false
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
				static = false
			}
			interp = interp || p.Type == elf.PT_INTERP
		}
		if f.Type == elf.ET_DYN && !interp {
			if names, err := f.DynString(elf.DT_SONAME); err == nil && len(names) > 0 && strings.HasPrefix(names[0], "ld-") {
				loader = true
			}
		}
		if static && f.Section(".symtab") == nil {
			add(trait{0.1, "static and stripped"})
		}
		f.Close()
	}
	seen := map[string]bool{}
	for _, s := range elfStrings {
		if loader && preloadTraits[s.t.reason] {
			continue
		}
		if !seen[s.t.reason] && bytes.Contains(b, s.needle) {
			seen[s.t.reason] = true
			add(s.t)
		}
	}
	if score > 0.99 {
		score = 0.99
	}
	return score, reasons, true
}
