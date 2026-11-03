package mlscore

// Raw features of EMBER2024 (feature version 3), as thrember computes them
// with pefile, for the groups the agent reproduces: general, histogram,
// byteentropy, strings, header, section, imports, exports, datadirectories,
// richheader. The PE parsing below follows pefile's rules where they shape
// the values (sections sorted by address and adjusted to the alignments,
// get_data clipping, overlay start, import name validation, ordinal names,
// the Rich header search), so the vector matches the training data.
// ml/v3/compare.py checks it against ml/v3/reference.py.

import (
	"bytes"
	"encoding/binary"
	"math"
	"regexp"
	"sort"
	"strings"
)

// RawV3 is the JSON shape of ml/v3/reference.py.
type RawV3 struct {
	General     GeneralV3           `json:"general"`
	Histogram   []int               `json:"histogram"`
	ByteEntropy []int               `json:"byteentropy"`
	Strings     StringsV3           `json:"strings"`
	Header      *HeaderV3           `json:"header"`
	Section     *SectionInfoV3      `json:"section"`
	Imports     map[string][]string `json:"imports"`
	ImportOrder []string            `json:"-"` // dll names as found (the last descriptor of a name wins)
	Exports     []string            `json:"exports"`
	DataDirs    []map[string]any    `json:"datadirectories"`
	Rich        []uint32            `json:"richheader"`
}

type GeneralV3 struct {
	Size       int     `json:"size"`
	Entropy    float64 `json:"entropy"`
	IsPE       int     `json:"is_pe"`
	StartBytes [4]int  `json:"start_bytes"`
}

type StringsV3 struct {
	NumStrings    int            `json:"numstrings"`
	AvLength      float64        `json:"avlength"`
	PrintableDist []int          `json:"printabledist"`
	Printables    int            `json:"printables"`
	Entropy       float64        `json:"entropy"`
	Counts        map[string]int `json:"string_counts"`
}

type HeaderV3 struct {
	Coff     CoffV3           `json:"coff"`
	Optional map[string]any   `json:"optional"`
	Dos      map[string]int64 `json:"dos"`
}

type CoffV3 struct {
	Timestamp            uint32   `json:"timestamp"`
	Machine              string   `json:"machine"`
	NumberOfSections     uint16   `json:"number_of_sections"`
	NumberOfSymbols      uint32   `json:"number_of_symbols"`
	SizeOfOptionalHeader uint16   `json:"sizeof_optional_header"`
	PointerToSymbolTable uint32   `json:"pointer_to_symbol_table"`
	Characteristics      []string `json:"characteristics"`
}

type SectionV3 struct {
	Name       string   `json:"name"`
	Size       uint32   `json:"size"`
	Entropy    float64  `json:"entropy"`
	VSize      uint32   `json:"vsize"`
	SizeRatio  float64  `json:"size_ratio"`
	VSizeRatio float64  `json:"vsize_ratio"`
	Props      []string `json:"props"`
}

type OverlayV3 struct {
	Size      int     `json:"size"`
	SizeRatio float64 `json:"size_ratio"`
	Entropy   float64 `json:"entropy"`
}

type SectionInfoV3 struct {
	Entry    string      `json:"entry"`
	Sections []SectionV3 `json:"sections"`
	Overlay  OverlayV3   `json:"overlay"`
}

// entropyH is pefile's entropy_H.
func entropyH(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var c [256]int
	for _, x := range b {
		c[x]++
	}
	e := 0.0
	n := float64(len(b))
	for _, k := range c {
		if k > 0 {
			p := float64(k) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// ---- strings ----

var v3StringRegexes = func() map[string]*regexp.Regexp {
	m := map[string]string{
		"url":          `\b(?:http|https|ftp)://[a-zA-Z0-9-._~:?#\[\]@!$&'()*+,;=]+`,
		"ipv4_addr":    `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
		"ipv6_addr":    `\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\b`,
		"mac_addr":     `\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b`,
		"email_addr":   `\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b`,
		"btc_wallet":   `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`,
		"file_path":    `\bC:/`,
		"dos_msg":      `!This program `,
		"registry_key": `\b(?:KHEY_|KHLM|HKCU)`,
		"/dev/":        `/dev/`, "/proc/": `/proc/`, "/bin/": `/bin/`, "/usr/": `/usr/`, "/tmp/": `/tmp/`,
		"/URI": `/URI`, "/FlateDecode": `/FlateDecode`, "/EmbeddedFile": `/EmbeddedFile`,
		"html": `(?i)html`, "javascript": `(?i)javascript`, "<script": `(?i)<script`, ".click(": `(?i).click`,
		"onlick":     `(?i)onclick`,
		"powershell": `(?i)powershell`, "Invoke-Expression": `Invoke-Expression`, "Invoke-Command": `Invoke-Command`,
		"Start-process": `Start-process`,
		"get":           `(?i)GET /`, "post": `(?i)POST /`, "http": `(?i)HTTP/`, "http://": `(?i)http://`,
		"https://": `(?i)https://`, "ftp": `(?i)ftp:`, "useragent": `(?i)User-Agent`, "cookie": `(?i)cookie`,
		"internet": `(?i)internet`, "download": `(?i)download`, "connect": `(?i)connect`,
		"base64":       `(?i)base64`, // as thrember wrote it: "+" is a quantifier there ("9" repeated), kept as is
		"base64string": `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`,
		"crypt":        `crypt`, "encode": `(?i)encode`, "decode": `(?i)decode`,
	}
	for _, w := range []string{"cache", "certificate", "clipboard", "command", "create", "debug", "delete", "desktop",
		"directory", "disk", "environment", "enum", "exit", "file", "hostname", "install", "hidden", "keyboard",
		"memory", "module", "mutex", "password", "privilege", "process", "remote", "resource", "security", "service",
		"shell", "snapshot", "system", "thread", "token", "wallet", "window"} {
		m[w] = "(?i)" + w
	}
	out := map[string]*regexp.Regexp{}
	for k, v := range m {
		out[k] = regexp.MustCompile(v)
	}
	return out
}()

// V3StringKeys are the string_counts keys in sorted order (the vector's order).
var V3StringKeys = func() []string {
	var ks []string
	for k := range v3StringRegexes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}()

// v3Literal: patterns that are a plain substring (case-sensitive), checked
// with bytes.Contains; the rest use the regexp.
var v3Literal = func() map[string][]byte {
	out := map[string][]byte{}
	for k, re := range v3StringRegexes {
		if lit, complete := re.LiteralPrefix(); complete {
			out[k] = []byte(lit)
		}
	}
	return out
}()

func stringsV3(b []byte) StringsV3 {
	out := StringsV3{PrintableDist: make([]int, 96), Counts: map[string]int{}}
	total := 0
	var all [][]byte
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 5 {
			all = append(all, b[start:end])
		}
		start = -1
	}
	for i, c := range b {
		if c >= 0x20 && c <= 0x7f {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(b))
	for _, s := range all {
		total += len(s)
		for _, c := range s {
			out.PrintableDist[c-0x20]++
		}
		lower := bytes.ToLower(s)
		for k, re := range v3StringRegexes {
			var hit bool
			if lit, ok := v3Literal[k]; ok {
				hit = bytes.Contains(s, lit)
			} else if strings.HasPrefix(re.String(), "(?i)") && isPlainWord(re.String()[4:]) {
				hit = bytes.Contains(lower, []byte(strings.ToLower(re.String()[4:])))
			} else {
				hit = re.Match(s)
			}
			if hit {
				out.Counts[k]++
			}
		}
	}
	out.NumStrings = len(all)
	out.Printables = total
	if len(all) > 0 {
		out.AvLength = float64(total) / float64(len(all))
		// entropy in float32, as numpy computes it there
		h := float32(0)
		for _, c := range out.PrintableDist {
			if c > 0 {
				p := float32(c) / float32(total)
				h += -p * float32(math.Log2(float64(p)))
			}
		}
		out.Entropy = float64(h)
	}
	return out
}

func isPlainWord(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ' ' || c == '/' || c == ':' || c == '<') {
			return false
		}
	}
	return s != ""
}

// ---- PE parsing (pefile semantics) ----

type peSection struct {
	name                                []byte
	vsize, va, rawSize, rawPtr, charact uint32
	nextVA                              int64 // -1: none
}

type peFile struct {
	data                 []byte
	optOff               int // file offset of the optional header
	sizeOfOptHeader      int
	is64                 bool
	sectAlign, fileAlign uint32
	sizeOfHeaders        uint32
	imageBase            uint64
	entry                uint32
	dirs                 [][2]uint32 // size, va
	sections             []peSection
	numberOfRvaAndSizes  uint32
	optFields            map[string]any
	coff                 CoffV3
	lastSection          int
}

func u16(b []byte, o int) uint16 {
	if o < 0 || o+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[o:])
}

func u32(b []byte, o int) uint32 {
	if o < 0 || o+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[o:])
}

func u64(b []byte, o int) uint64 {
	if o < 0 || o+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[o:])
}

func adjSectionAlignment(val, sa, fa uint32) uint32 {
	if sa < 0x1000 {
		sa = fa
	}
	if sa != 0 && val%sa != 0 {
		return sa * (val / sa)
	}
	return val
}

func (p *peFile) ptrAdj(s *peSection) int64 {
	ptr := int64(s.rawPtr &^ 0x1ff)
	if p.sectAlign < 0x1000 && s.rawPtr == s.va {
		ptr = int64(s.va)
	}
	return ptr
}

func (p *peFile) vaAdj(s *peSection) int64 {
	return int64(adjSectionAlignment(s.va, p.sectAlign, p.fileAlign))
}

func (p *peFile) containsRVA(s *peSection, rva int64) bool {
	va := p.vaAdj(s)
	var size int64
	if int64(len(p.data))-p.ptrAdj(s) < int64(s.rawSize) {
		size = int64(s.vsize)
	} else {
		size = max(int64(s.rawSize), int64(s.vsize))
	}
	if s.nextVA >= 0 && s.nextVA > int64(s.va) && va+size > s.nextVA {
		size = s.nextVA - va
	}
	return va <= rva && rva < va+size
}

func (p *peFile) sectionByRVA(rva int64) *peSection {
	if p.lastSection >= 0 && p.containsRVA(&p.sections[p.lastSection], rva) {
		return &p.sections[p.lastSection]
	}
	for i := range p.sections {
		if p.containsRVA(&p.sections[i], rva) {
			p.lastSection = i
			return &p.sections[i]
		}
	}
	return nil
}

// sectionData is pefile's SectionStructure.get_data(start, length).
func (p *peFile) sectionData(s *peSection, start int64, length int64) []byte {
	var off int64
	if start < 0 {
		off = p.ptrAdj(s)
	} else {
		off = start - p.vaAdj(s) + p.ptrAdj(s)
	}
	var end int64
	if length >= 0 {
		end = off + length
	} else {
		end = off + int64(s.rawSize)
	}
	if lim := int64(s.rawPtr) + int64(s.rawSize); end > lim {
		end = lim
	}
	return pySlice(p.data, off, end)
}

// pySlice is Python's data[a:b] (negative a or b count from the end).
func pySlice(d []byte, a, b int64) []byte {
	n := int64(len(d))
	if a < 0 {
		a = max(n+a, 0)
	}
	if b < 0 {
		b = max(n+b, 0)
	}
	a, b = min(a, n), min(b, n)
	if a >= b {
		return nil
	}
	return d[a:b]
}

// getData is pefile's PE.get_data(rva, length); ok false is PEFormatError.
func (p *peFile) getData(rva int64, length int64) ([]byte, bool) {
	s := p.sectionByRVA(rva)
	if s == nil {
		if rva < int64(len(p.data)) {
			end := int64(len(p.data))
			if length >= 0 {
				end = rva + length
			}
			return pySlice(p.data, rva, end), true
		}
		return nil, false
	}
	return p.sectionData(s, rva, length), true
}

func (p *peFile) offsetFromRVA(rva int64) (int64, bool) {
	s := p.sectionByRVA(rva)
	if s == nil {
		if rva < int64(len(p.data)) {
			return rva, true
		}
		return 0, false
	}
	return rva - p.vaAdj(s) + p.ptrAdj(s), true
}

func (p *peFile) stringAtRVA(rva int64, maxLen int64) []byte {
	var d []byte
	if s := p.sectionByRVA(rva); s == nil {
		d = pySlice(p.data, rva, rva+maxLen)
	} else {
		d = p.sectionData(s, rva, maxLen)
	}
	if i := bytes.IndexByte(d, 0); i >= 0 {
		d = d[:i]
	}
	return d
}

// parsePE parses like pefile.PE(data=b); ok false when pefile would raise.
func parsePE(b []byte) (*peFile, bool) {
	if len(b) < 64 || b[0] != 'M' || b[1] != 'Z' {
		return nil, false
	}
	lfanew := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if lfanew < 0 || lfanew > len(b) || lfanew+4 > len(b) || !bytes.Equal(b[lfanew:lfanew+4], []byte("PE\x00\x00")) {
		return nil, false
	}
	fh := lfanew + 4
	if fh+20 > len(b) {
		return nil, false
	}
	p := &peFile{data: b, optOff: fh + 20, lastSection: -1}
	p.coff = CoffV3{
		Machine:              "IMAGE_FILE_MACHINE_UNKNOWN",
		NumberOfSections:     u16(b, fh+2),
		Timestamp:            u32(b, fh+4),
		PointerToSymbolTable: u32(b, fh+8),
		NumberOfSymbols:      u32(b, fh+12),
		SizeOfOptionalHeader: u16(b, fh+16),
	}
	if m, ok := pefileMachine[u16(b, fh)]; ok {
		p.coff.Machine = m
	}
	ch := uint32(u16(b, fh+18))
	p.coff.Characteristics = []string{}
	for _, f := range pefileImageFlags {
		if f.bit&ch != 0 {
			p.coff.Characteristics = append(p.coff.Characteristics, f.name)
		}
	}
	p.sizeOfOptHeader = int(p.coff.SizeOfOptionalHeader)
	o := p.optOff
	// pefile pads a short optional header with zeros
	opt := make([]byte, 240)
	copy(opt, b[min(o, len(b)):])
	magic := binary.LittleEndian.Uint16(opt)
	switch magic {
	case 0x10b:
	case 0x20b:
		p.is64 = true
	default:
		return nil, false
	}
	f := map[string]any{"magic": magic}
	r16 := func(off int) uint16 { return binary.LittleEndian.Uint16(opt[off:]) }
	r32 := func(off int) uint32 { return binary.LittleEndian.Uint32(opt[off:]) }
	f["major_linker_version"] = opt[2]
	f["minor_linker_version"] = opt[3]
	f["sizeof_code"] = r32(4)
	f["sizeof_initialized_data"] = r32(8)
	f["sizeof_uninitialized_data"] = r32(12)
	p.entry = r32(16)
	f["address_of_entrypoint"] = p.entry
	f["base_of_code"] = r32(20)
	var dllChars uint16
	var dirOff int
	if p.is64 {
		p.imageBase = binary.LittleEndian.Uint64(opt[24:])
		p.sectAlign, p.fileAlign = r32(32), r32(36)
		f["major_operating_system_version"], f["minor_operating_system_version"] = r16(40), r16(42)
		f["major_image_version"], f["minor_image_version"] = r16(44), r16(46)
		f["major_subsystem_version"], f["minor_subsystem_version"] = r16(48), r16(50)
		f["sizeof_image"], p.sizeOfHeaders = r32(56), r32(60)
		f["checksum"] = r32(64)
		f["subsystem"] = r16(68)
		dllChars = r16(70)
		f["sizeof_stack_reserve"] = binary.LittleEndian.Uint64(opt[72:])
		f["sizeof_stack_commit"] = binary.LittleEndian.Uint64(opt[80:])
		f["sizeof_heap_reserve"] = binary.LittleEndian.Uint64(opt[88:])
		f["sizeof_heap_commit"] = binary.LittleEndian.Uint64(opt[96:])
		p.numberOfRvaAndSizes = r32(108)
		dirOff = o + 112
	} else {
		p.imageBase = uint64(r32(28))
		p.sectAlign, p.fileAlign = r32(32), r32(36)
		f["major_operating_system_version"], f["minor_operating_system_version"] = r16(40), r16(42)
		f["major_image_version"], f["minor_image_version"] = r16(44), r16(46)
		f["major_subsystem_version"], f["minor_subsystem_version"] = r16(48), r16(50)
		f["sizeof_image"], p.sizeOfHeaders = r32(56), r32(60)
		f["checksum"] = r32(64)
		f["subsystem"] = r16(68)
		dllChars = r16(70)
		f["sizeof_stack_reserve"] = uint64(r32(72))
		f["sizeof_stack_commit"] = uint64(r32(76))
		f["sizeof_heap_reserve"] = uint64(r32(80))
		f["sizeof_heap_commit"] = uint64(r32(84))
		p.numberOfRvaAndSizes = r32(92)
		dirOff = o + 96
	}
	f["sizeof_headers"] = p.sizeOfHeaders
	f["image_base"] = p.imageBase
	f["section_alignment"] = p.sectAlign
	f["number_of_rvas_and_sizes"] = p.numberOfRvaAndSizes
	sub := "IMAGE_SUBSYSTEM_UNKNOWN"
	if s, ok := pefileSubsystem[f["subsystem"].(uint16)]; ok {
		sub = s
	}
	f["subsystem"] = sub
	dc := []string{}
	for _, fl := range pefileDllFlags {
		if fl.bit&uint32(dllChars) != 0 {
			dc = append(dc, fl.name)
		}
	}
	f["dll_characteristics"] = dc
	p.optFields = f

	// data directories: at most 16, as many as NumberOfRvaAndSizes says and
	// the file holds (a short last entry is zero-padded)
	n := int(p.numberOfRvaAndSizes & 0x7fffffff)
	for i := 0; i < n && i < 16; i++ {
		off := dirOff + 8*i
		if len(b)-off <= 0 {
			break
		}
		e := make([]byte, 8)
		copy(e, b[off:])
		p.dirs = append(p.dirs, [2]uint32{binary.LittleEndian.Uint32(e[4:]), binary.LittleEndian.Uint32(e)})
	}

	// sections
	so := o + p.sizeOfOptHeader
	for i := 0; i < int(p.coff.NumberOfSections) && i < 0x800; i++ {
		off := so + 40*i
		if off >= len(b) {
			break
		}
		h := make([]byte, 40)
		k := copy(h, b[off:])
		if k == 0 || bytes.Count(h[:k], []byte{0}) == 40 {
			break
		}
		s := peSection{name: h[:8], vsize: binary.LittleEndian.Uint32(h[8:]), va: binary.LittleEndian.Uint32(h[12:]),
			rawSize: binary.LittleEndian.Uint32(h[16:]), rawPtr: binary.LittleEndian.Uint32(h[20:]),
			charact: binary.LittleEndian.Uint32(h[36:])}
		errs := 0
		if int64(s.rawSize)+int64(s.rawPtr) > int64(len(b)) {
			errs++
		}
		if int64(s.rawPtr&^0x1ff) > int64(len(b)) {
			errs++
		}
		if s.vsize > 0x10000000 {
			errs++
		}
		if adjSectionAlignment(s.va, p.sectAlign, p.fileAlign) > 0x10000000 {
			errs++
		}
		if p.fileAlign != 0 && s.rawPtr%p.fileAlign != 0 {
			errs++
		}
		if errs >= 3 {
			break
		}
		p.sections = append(p.sections, s)
	}
	sort.SliceStable(p.sections, func(i, j int) bool { return p.sections[i].va < p.sections[j].va })
	for i := range p.sections {
		p.sections[i].nextVA = -1
		if i+1 < len(p.sections) {
			p.sections[i].nextVA = int64(p.sections[i+1].va)
		}
	}
	return p, true
}

func sectionName(n []byte) string {
	n = bytes.Trim(n, "\x00")
	return strings.ToLower(decodeIgnore(n))
}

// decodeIgnore is Python's bytes.decode(errors="ignore") (UTF-8).
func decodeIgnore(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8DecodeRune(b)
		if r >= 0 {
			sb.WriteRune(r)
		}
		b = b[size:]
	}
	return sb.String()
}

func (p *peFile) sectionInfo() *SectionInfoV3 {
	out := &SectionInfoV3{Sections: []SectionV3{}}
	for i := range p.sections {
		if p.containsRVA(&p.sections[i], int64(p.entry)) {
			out.Entry = sectionName(p.sections[i].name)
		}
	}
	for i := 0; out.Entry == "" && i < len(p.sections); i++ {
		if p.sections[i].charact&0x20000000 != 0 {
			out.Entry = sectionName(p.sections[i].name)
		}
	}
	for i := range p.sections {
		s := &p.sections[i]
		props := []string{}
		for _, f := range pefileSectionFlags {
			if f.bit&s.charact != 0 {
				props = append(props, f.name)
			}
		}
		out.Sections = append(out.Sections, SectionV3{
			Name: sectionName(s.name), Size: s.rawSize, Entropy: entropyH(p.sectionData(s, -1, -1)), VSize: s.vsize,
			SizeRatio: float64(s.rawSize) / float64(len(p.data)), VSizeRatio: float64(s.rawSize) / float64(max(s.vsize, 1)),
			Props: props,
		})
	}
	if start, ok := p.overlayStart(); ok {
		ov := p.data[start:]
		out.Overlay = OverlayV3{Size: len(ov), SizeRatio: float64(len(ov)) / float64(len(p.data)), Entropy: entropyH(ov)}
	}
	return out
}

// overlayStart is pefile's get_overlay_data_start_offset.
func (p *peFile) overlayStart() (int64, bool) {
	fileSize := int64(len(p.data))
	best := [2]int64{0, 0}
	upd := func(off, size int64) {
		if best[0]+best[1] < off+size && off+size <= fileSize {
			best = [2]int64{off, size}
		}
	}
	upd(int64(p.optOff), int64(p.sizeOfOptHeader))
	for _, s := range p.sections {
		upd(int64(s.rawPtr), int64(s.rawSize))
	}
	for i, d := range p.dirs {
		if i == 4 { // SECURITY: the signature is overlay
			continue
		}
		off, ok := p.offsetFromRVA(int64(d[1]))
		if !ok {
			continue
		}
		upd(off, int64(d[0]))
	}
	if fileSize > best[0]+best[1] {
		return best[0] + best[1], true
	}
	return 0, false
}

func validDosFilename(s []byte) bool {
	for _, c := range s {
		if bytes.IndexByte(pefileAllowedFilename, c) < 0 && c != '\\' && c != '/' {
			return false
		}
	}
	return true
}

func validFunctionName(s []byte) bool {
	for _, c := range s {
		if bytes.IndexByte(pefileAllowedFunctionName, c) < 0 && bytes.IndexByte([]byte("._?@$()<>"), c) < 0 {
			return false
		}
	}
	return true
}

type thunk struct {
	addr uint64
}

// importTable is pefile's get_import_table; nil, false is "None" (an error).
func (p *peFile) importTable(rva int64, maxLen int64, total *int) ([]thunk, bool) {
	var table []thunk
	size := int64(4)
	ordFlag := uint64(0x80000000)
	if p.is64 {
		size, ordFlag = 8, 0x8000000000000000
	}
	start := rva
	repeated := 0
	seen32, seen64 := map[uint64]bool{}, map[uint64]bool{}
	var min32, max32, min64, max64 uint64 = math.MaxUint64, 0, math.MaxUint64, 0
	for rva != 0 {
		if maxLen >= 0 && rva >= start+maxLen {
			break
		}
		if *total > 0x2000 {
			break
		}
		*total++
		if repeated >= 15 {
			return nil, true
		}
		if max32 > min32 && max32-min32 > 128<<20 || max64 > min64 && max64-min64 > 128<<20 {
			return nil, true
		}
		d, ok := p.getData(rva, size)
		if !ok || int64(len(d)) != size {
			return nil, false
		}
		var a uint64
		if p.is64 {
			a = binary.LittleEndian.Uint64(d)
		} else {
			a = uint64(binary.LittleEndian.Uint32(d))
		}
		if a >= uint64(start) && a <= uint64(rva) {
			break
		}
		if a != 0 {
			if a&ordFlag != 0 {
				if a&0x7fffffff > 0xffff {
					return nil, true
				}
			} else if a >= 1<<32 {
				if seen64[a] {
					repeated++
				}
				seen64[a] = true
				min64, max64 = min(min64, a), max(max64, a)
			} else {
				if seen32[a] {
					repeated++
				}
				seen32[a] = true
				min32, max32 = min(min32, a), max(max32, a)
			}
		}
		if a == 0 {
			break
		}
		rva += size
		table = append(table, thunk{a})
	}
	return table, true
}

// imports is pefile's parse_import_directory + thrember's ImportsInfo.
func (p *peFile) imports() (map[string][]string, []string, bool) {
	out := map[string][]string{}
	var order []string
	if len(p.dirs) < 2 || p.dirs[1][1] == 0 || p.dirs[1][0] == 0 {
		return out, order, true
	}
	rva := int64(p.dirs[1][1])
	errors := 0
	total := 0
	ordFlag := uint64(0x80000000)
	mask := uint64(0x7fffffff)
	if p.is64 {
		ordFlag, mask = 0x8000000000000000, 0x7fffffffffffffff
	}
	for {
		d, ok := p.getData(rva, 20)
		if !ok {
			break
		}
		fileOff, _ := p.offsetFromRVA(rva)
		if len(d) == 0 || bytes.Count(d, []byte{0}) == len(d) {
			break
		}
		desc := make([]byte, 20)
		copy(desc, d)
		oft, nameRVA, ft := binary.LittleEndian.Uint32(desc), binary.LittleEndian.Uint32(desc[12:]), binary.LittleEndian.Uint32(desc[16:])
		rva += 20
		maxLen := int64(len(p.data)) - fileOff
		if rva > int64(oft) || rva > int64(ft) {
			maxLen = max(rva-int64(oft), rva-int64(ft))
		}
		ilt, iltOK := p.importTable(int64(oft), maxLen, &total)
		iat, iatOK := p.importTable(int64(ft), maxLen, &total)
		var names []string
		var symbols bool
		if len(ilt) == 0 && len(iat) == 0 {
			symbols = false
		} else {
			table := ilt
			if len(table) == 0 {
				table = iat
			}
			_ = iltOK
			_ = iatOK
			numInvalid := 0
			aborted := false
			type sym struct {
				name []byte
				ord  int
			}
			var syms []sym
			for idx, t := range table {
				var name []byte
				ord := -1
				haveName := false
				if t.addr != 0 {
					if t.addr&ordFlag != 0 {
						ord = int(t.addr & 0xffff)
					} else {
						hint := int64(t.addr & mask)
						if _, ok := p.getData(hint, 2); ok {
							name = p.stringAtRVA(int64(t.addr)+2, 0x200)
							haveName = true
							if !validFunctionName(name) {
								name = []byte("*invalid*")
							}
						}
					}
				}
				if ord < 0 && !haveName {
					aborted = true
					break
				}
				if haveName && string(name) == "*invalid*" {
					if numInvalid > 1000 && numInvalid == idx {
						aborted = true
						break
					}
					numInvalid++
					continue
				}
				if ord > 0 || (haveName && len(name) > 0) {
					syms = append(syms, sym{name, ord})
				}
			}
			if aborted {
				syms = nil
			}
			symbols = len(syms) > 0
			if symbols {
				dll := p.stringAtRVA(int64(nameRVA), 0x200)
				if !validDosFilename(dll) {
					dll = []byte("*invalid*")
				}
				if len(dll) > 0 {
					dllName := string(dll)
					for _, s := range syms {
						switch {
						case len(s.name) > 0:
							n := string(s.name)
							if len(n) > 10000 {
								n = n[:10000]
							}
							names = append(names, n)
						default:
							if fn, ok := pefileOrdNames[strings.ToLower(dllName)][uint16(s.ord)]; ok {
								names = append(names, fn)
							} else {
								names = append(names, dllName+":ordinal"+itoa(s.ord))
							}
						}
					}
					if _, seen := out[dllName]; !seen {
						order = append(order, dllName)
					}
					out[dllName] = names
				}
			}
		}
		if errors > 5 {
			break
		}
		if !symbols {
			errors++
			continue
		}
	}
	return out, order, true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// exports is pefile's parse_export_directory (names and ordinals) +
// thrember's ExportsInfo.
func (p *peFile) exports() []string {
	out := []string{}
	if len(p.dirs) < 1 || p.dirs[0][1] == 0 {
		return out
	}
	d, ok := p.getData(int64(p.dirs[0][1]), 40)
	if !ok || len(d) < 40 {
		return out
	}
	base := binary.LittleEndian.Uint32(d[16:])
	nFuncs := binary.LittleEndian.Uint32(d[20:])
	nNames := binary.LittleEndian.Uint32(d[24:])
	addrFuncs := int64(binary.LittleEndian.Uint32(d[28:]))
	addrNames := int64(binary.LittleEndian.Uint32(d[32:]))
	addrOrds := int64(binary.LittleEndian.Uint32(d[36:]))
	// pefile reads the tables up to the end of the section or file
	if nFuncs > 0x2000 || nNames > 0x2000 {
		return out
	}
	names, _ := p.getData(addrNames, int64(nNames)*4)
	ords, _ := p.getData(addrOrds, int64(nNames)*2)
	funcs, _ := p.getData(addrFuncs, int64(nFuncs)*4)
	named := map[uint32]bool{}
	for i := uint32(0); i < nNames; i++ {
		if int(4*i+4) > len(names) || int(2*i+2) > len(ords) {
			break
		}
		nameRVA := int64(binary.LittleEndian.Uint32(names[4*i:]))
		idx := uint32(binary.LittleEndian.Uint16(ords[2*i:]))
		if idx >= nFuncs || int(4*idx+4) > len(funcs) {
			continue
		}
		name := p.stringAtRVA(nameRVA, 0x200)
		if !validFunctionName(name) {
			continue
		}
		named[idx] = true
		if len(name) > 0 {
			n := string(name)
			if len(n) > 10000 {
				n = n[:10000]
			}
			out = append(out, n)
		}
	}
	for idx := uint32(0); idx < nFuncs; idx++ {
		if named[idx] || int(4*idx+4) > len(funcs) {
			continue
		}
		if binary.LittleEndian.Uint32(funcs[4*idx:]) == 0 {
			continue
		}
		out = append(out, "ordinal"+itoa(int(base+idx)))
	}
	return out
}

func (p *peFile) hasRelocs() bool {
	if len(p.dirs) < 6 || p.dirs[5][1] == 0 || p.dirs[5][0] == 0 {
		return false
	}
	d, ok := p.getData(int64(p.dirs[5][1]), 8)
	if !ok || len(d) < 8 {
		return false
	}
	size := binary.LittleEndian.Uint32(d[4:])
	return size >= 8 && size <= p.dirs[5][0]+8 && binary.LittleEndian.Uint32(d) != 0 || size >= 8
}

func (p *peFile) dataDirs() []map[string]any {
	names := []string{"EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "COPYRIGHT",
		"GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"}
	rel := 0
	if p.hasRelocs() {
		rel = 1
	}
	out := []map[string]any{{"has_relocs": rel, "has_dynamic_relocs": 0}}
	for i, d := range p.dirs {
		out = append(out, map[string]any{"name": names[i], "size": d[0], "virtual_address": d[1]})
	}
	return out
}

// rich is pefile's parse_rich_header values.
func (p *peFile) rich() []uint32 {
	const dans, richMagic = 0x536E6144, 0x68636952
	end := p.optOff
	if end > len(p.data) {
		end = len(p.data)
	}
	if end <= 0x80 {
		return []uint32{}
	}
	i := bytes.Index(p.data[0x80:end], []byte("Rich"))
	if i < 0 {
		return []uint32{}
	}
	ri := 0x80 + i
	rd := pySlice(p.data, 0x80, int64(ri+8))
	rd = rd[:4*(len(rd)/4)]
	words := make([]uint32, len(rd)/4)
	for k := range words {
		words[k] = binary.LittleEndian.Uint32(rd[4*k:])
	}
	at := -1
	for k, w := range words {
		if w == richMagic {
			at = k
			break
		}
	}
	if at < 0 || at+1 >= len(words) {
		return []uint32{}
	}
	key := words[at+1]
	vals := []uint32{}
	rest := words[min(4, len(words)):]
	for k := 0; k < len(rest)/2; k++ {
		if rest[2*k] == richMagic {
			break
		}
		vals = append(vals, rest[2*k]^key, rest[2*k+1]^key)
	}
	_ = dans
	return vals
}

func (p *peFile) header() *HeaderV3 {
	h := &HeaderV3{Coff: p.coff, Optional: p.optFields, Dos: map[string]int64{}}
	names := []string{"e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp",
		"e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno"}
	for i, n := range names {
		h.Dos[n] = int64(u16(p.data, 2*i))
	}
	h.Dos["e_oemid"] = int64(u16(p.data, 36))
	h.Dos["e_oeminfo"] = int64(u16(p.data, 38))
	h.Dos["e_lfanew"] = int64(u32(p.data, 60))
	return h
}

// ExtractV3 computes the raw v3 features of a file (any file: the PE groups
// are empty when it is not a PE pefile accepts).
func ExtractV3(b []byte) *RawV3 {
	r := &RawV3{Histogram: make([]int, 256), Imports: map[string][]string{}, Exports: []string{},
		DataDirs: []map[string]any{}, Rich: []uint32{}}
	r.General = GeneralV3{Size: len(b), Entropy: entropyH(b)}
	for i := 0; i < 4 && i < len(b); i++ {
		r.General.StartBytes[i] = int(b[i])
	}
	for _, c := range b {
		r.Histogram[c]++
	}
	be := byteEntropyCounts(b)
	r.ByteEntropy = be[:]
	r.Strings = stringsV3(b)
	p, ok := parsePE(b)
	if !ok {
		return r
	}
	r.General.IsPE = 1
	r.Header = p.header()
	r.Section = p.sectionInfo()
	r.Imports, r.ImportOrder, _ = p.imports()
	r.Exports = p.exports()
	r.DataDirs = p.dataDirs()
	r.Rich = p.rich()
	return r
}
