// agent/internal/task/plugins_filefeatures.go
package task

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// filefeatures describes one file for malware triage and YARA drafting
// without sending it anywhere: hashes, type, entropy, PE/ELF metadata,
// packer hints and a bounded set of printable strings with offsets.
// Credential-shaped strings are redacted here, before they leave the host.
// Read-only: the file is opened for reading and never executed.

const (
	ffDefaultMaxSize    = 64 << 20 // bytes analysed; hashes always cover the whole file
	ffDefaultMaxStrings = 300
	ffDefaultMinLen     = 6
	ffMaxCandidates     = 20000
	ffMaxListed         = 400 // imports, exports, symbols
	ffMaxStringLen      = 200
)

var ffSecretPatterns = []struct {
	kind string
	rx   *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY`)},
	{"AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{"JSON web token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.`)},
	{"credential assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passw(or)?d)\s*[:=]\s*\S{12,}`)},
}

var (
	ffPDB         = regexp.MustCompile(`[\x20-\x7e]{4,260}\.pdb`)
	ffInteresting = regexp.MustCompile(`(?i)https?://|\\\\|[a-z]:\\|/tmp/|/dev/shm|/etc/|hkey_|software\\|\.(exe|dll|ps1|bat|vbs|sh|so)\b|` +
		`cmd\.exe|powershell|rundll32|regsvr32|schtasks|wget|curl|base64|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`createremotethread|virtualalloc|writeprocessmemory|ptrace|mprotect|keylog|inject|mutex|\.onion`)
	ffPackerSections = map[string]string{
		"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
		".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS", ".petite": "Petite", ".themida": "Themida",
		".vmp0": "VMProtect", ".vmp1": "VMProtect", ".nsp0": "NsPack", ".enigma1": "Enigma",
	}
)

func pluginFileFeatures(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	path := argString(args, "path", "")
	if path == "" {
		return fmt.Errorf("path is required")
	}
	maxSize := int64(argInt(args, "max_size", ffDefaultMaxSize))
	maxStrings := argInt(args, "max_strings", ffDefaultMaxStrings)
	minLen := argInt(args, "min_len", ffDefaultMinLen)
	if minLen < 4 {
		minLen = 4
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	m, s1, s256 := md5.New(), sha1.New(), sha256.New()
	hashers := io.MultiWriter(m, s1, s256)
	var head bytes.Buffer
	if _, err := io.Copy(io.MultiWriter(&head, hashers), io.LimitReader(ctxReader{ctx, f}, maxSize)); err != nil {
		return err
	}
	if _, err := io.Copy(hashers, ctxReader{ctx, f}); err != nil { // the rest: hashed, not analysed
		return err
	}
	data := head.Bytes()

	row := map[string]any{
		"Path": path, "Size": info.Size(), "Truncated": info.Size() > int64(len(data)),
		"MD5": hex.EncodeToString(m.Sum(nil)), "SHA1": hex.EncodeToString(s1.Sum(nil)),
		"SHA256": hex.EncodeToString(s256.Sum(nil)),
		"Type":   ffType(data), "Entropy": round2(entropy(data)),
	}
	var packers []string
	switch row["Type"] {
	case "PE32", "PE32+":
		packers = ffPE(data, row)
	case "ELF":
		packers = ffELF(data, row)
	}
	if bytes.Contains(data, []byte("UPX!")) {
		packers = append(packers, "UPX! marker")
	}
	if e, _ := row["Entropy"].(float64); e > 7.2 {
		packers = append(packers, fmt.Sprintf("high overall entropy (%.2f)", e))
	}
	row["PackerIndicators"] = dedupe(packers)
	var pdbs []string
	for _, p := range ffPDB.FindAll(data, 5) {
		pdbs = append(pdbs, string(p))
	}
	row["PDB"] = dedupe(pdbs)
	strs, redacted := ffStrings(ctx, data, minLen, maxStrings)
	row["Strings"], row["Redacted"] = strs, redacted
	return emit(row)
}

func ffType(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		if f, err := pe.NewFile(bytes.NewReader(b)); err == nil {
			defer f.Close()
			if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
				return "PE32+"
			}
			return "PE32"
		}
		return "MZ (not a valid PE)"
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "ELF"
	case len(b) >= 4 && (binary.BigEndian.Uint32(b) == 0xcafebabe || binary.LittleEndian.Uint32(b)&0xfffffffe == 0xfeedface ||
		binary.BigEndian.Uint32(b)&0xfffffffe == 0xfeedface):
		return "Mach-O"
	case bytes.HasPrefix(b, []byte("%PDF")):
		return "PDF"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "ZIP"
	case bytes.HasPrefix(b, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
		return "OLE2"
	case bytes.HasPrefix(b, []byte("#!")):
		return "script"
	}
	printable := 0
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	for _, c := range sample {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	if len(sample) > 0 && printable*100/len(sample) > 95 {
		return "text"
	}
	return "data"
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	h, n := 0.0, float64(len(b))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func dedupe(in []string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func capList(in []string) []string {
	if len(in) > ffMaxListed {
		return in[:ffMaxListed]
	}
	return in
}

func ffPE(data []byte, row map[string]any) []string {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer f.Close()
	var packers []string
	row["Machine"] = fmt.Sprintf("0x%x", f.FileHeader.Machine)
	row["Timestamp"] = f.FileHeader.TimeDateStamp
	var sections []map[string]any
	for _, s := range f.Sections {
		raw, _ := s.Data()
		e := round2(entropy(raw))
		exec := s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0
		write := s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0
		sections = append(sections, map[string]any{
			"Name": s.Name, "VirtualSize": s.VirtualSize, "RawSize": s.Size, "Entropy": e,
			"Executable": exec, "Writable": write,
		})
		if p, ok := ffPackerSections[s.Name]; ok {
			packers = append(packers, p+" section "+s.Name)
		}
		if exec && e > 7.0 {
			packers = append(packers, fmt.Sprintf("executable section %s with entropy %.2f", s.Name, e))
		}
		if exec && write {
			packers = append(packers, "writable+executable section "+s.Name)
		}
	}
	row["Sections"] = sections
	var imports []string
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms { // "Func:dll.dll"
			if fn, dll, ok := strings.Cut(s, ":"); ok {
				imports = append(imports, strings.ToLower(dll)+"!"+fn)
			} else {
				imports = append(imports, s)
			}
		}
	}
	sort.Strings(imports)
	row["Imports"] = capList(imports)
	if len(imports) < 10 {
		packers = append(packers, fmt.Sprintf("only %d imports", len(imports)))
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		row["Libraries"] = capList(libs)
	}
	exportDir, securityDir := peDirs(f)
	row["Exports"] = capList(peExports(f, data, exportDir))
	row["HasSignature"] = securityDir.Size > 0 // presence only; verifying Authenticode is the analyst's step
	return packers
}

// peDirs: the export and security directories. NumberOfRvaAndSizes comes from
// the file and may claim more than the 16 slots that exist.
func peDirs(f *pe.File) (pe.DataDirectory, pe.DataDirectory) {
	var dd []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))]
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))]
	}
	var exp, sec pe.DataDirectory
	if len(dd) > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		exp = dd[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	}
	if len(dd) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
		sec = dd[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	}
	return exp, sec
}

// peExports reads export names from the export directory, with every offset bounds-checked.
func peExports(f *pe.File, data []byte, dir pe.DataDirectory) []string {
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	off := func(rva uint32) (int, bool) {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.Size {
				o := int(s.Offset) + int(rva-s.VirtualAddress)
				return o, o >= 0 && o < len(data)
			}
		}
		return 0, false
	}
	base, ok := off(dir.VirtualAddress)
	if !ok || base+40 > len(data) {
		return nil
	}
	count := binary.LittleEndian.Uint32(data[base+24:])
	namesRVA := binary.LittleEndian.Uint32(data[base+32:])
	names, ok := off(namesRVA)
	if !ok || count > 65535 {
		return nil
	}
	var out []string
	for i := 0; i < int(count) && len(out) < ffMaxListed; i++ {
		p := names + 4*i
		if p+4 > len(data) {
			break
		}
		so, ok := off(binary.LittleEndian.Uint32(data[p:]))
		if !ok {
			continue
		}
		end := bytes.IndexByte(data[so:min(so+256, len(data))], 0)
		if end > 0 {
			out = append(out, string(data[so:so+end]))
		}
	}
	return out
}

func ffELF(data []byte, row map[string]any) []string {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer f.Close()
	var packers []string
	row["Machine"], row["ELFType"] = f.Machine.String(), f.Type.String()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b := make([]byte, min(int(p.Filesz), 256))
			if _, err := p.ReadAt(b, 0); err == nil {
				row["Interpreter"] = strings.TrimRight(string(b), "\x00")
			}
		}
	}
	if len(f.Sections) == 0 {
		packers = append(packers, "no section headers")
	}
	var sections []map[string]any
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL || s.Type == elf.SHT_NOBITS {
			continue
		}
		raw, _ := s.Data()
		e := round2(entropy(raw))
		exec := s.Flags&elf.SHF_EXECINSTR != 0
		sections = append(sections, map[string]any{"Name": s.Name, "Size": s.Size, "Entropy": e, "Executable": exec})
		if exec && e > 7.0 {
			packers = append(packers, fmt.Sprintf("executable section %s with entropy %.2f", s.Name, e))
		}
	}
	row["Sections"] = sections
	if libs, err := f.ImportedLibraries(); err == nil {
		row["Libraries"] = capList(libs)
	}
	var imports, exports []string
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			imports = append(imports, s.Name)
		}
	}
	if dyn, err := f.DynamicSymbols(); err == nil {
		for _, s := range dyn {
			if s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC && elf.ST_BIND(s.Info) == elf.STB_GLOBAL {
				exports = append(exports, s.Name)
			}
		}
	}
	sort.Strings(imports)
	sort.Strings(exports)
	row["Imports"], row["Exports"] = capList(imports), capList(exports)
	return packers
}

type ffString struct {
	Offset   int
	Encoding string
	Value    string
	score    int
}

// ffStrings extracts ASCII and UTF-16LE runs, keeps the most telling ones
// (long, or naming paths, URLs, commands, APIs) and redacts credentials.
func ffStrings(ctx context.Context, data []byte, minLen, max int) ([]map[string]any, int) {
	var cands []ffString
	add := func(off int, enc, s string) {
		if len(cands) >= ffMaxCandidates || strings.Trim(s, " .-_=*#") == "" {
			return
		}
		score := min(len(s), 60)
		if ffInteresting.MatchString(s) {
			score += 100
		}
		if len(s) > ffMaxStringLen {
			s = s[:ffMaxStringLen]
		}
		cands = append(cands, ffString{off, enc, s, score})
	}
	start := -1
	for i := 0; i <= len(data); i++ {
		if i%(1<<20) == 0 && ctx.Err() != nil {
			break
		}
		if i < len(data) && data[i] >= 0x20 && data[i] < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			add(start, "ascii", string(data[start:i]))
		}
		start = -1
	}
	// UTF-16LE: printable byte followed by 0x00, repeated
	for i := 0; i+1 < len(data); {
		j := i
		var units []uint16
		for j+1 < len(data) && data[j+1] == 0 && data[j] >= 0x20 && data[j] < 0x7f {
			units = append(units, uint16(data[j]))
			j += 2
		}
		if len(units) >= minLen {
			add(i, "utf16le", string(utf16.Decode(units)))
			i = j
		} else {
			i++
		}
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].score > cands[b].score })
	if len(cands) > max {
		cands = cands[:max]
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].Offset < cands[b].Offset })
	out, redacted := make([]map[string]any, 0, len(cands)), 0
	for _, c := range cands {
		v := c.Value
		for _, p := range ffSecretPatterns {
			if p.rx.MatchString(v) {
				v = "[redacted: " + p.kind + "]"
				redacted++
				break
			}
		}
		out = append(out, map[string]any{"Offset": c.Offset, "Encoding": c.Encoding, "Value": v})
	}
	return out, redacted
}
