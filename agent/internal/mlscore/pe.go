package mlscore

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// EMBER's raw features (ember/features.py) computed with Go's debug/pe
// instead of LIEF. Names follow LIEF's enum names, which EMBER stored.

var (
	reStrings  = regexp.MustCompile(`[\x20-\x7f]{5,}`)
	rePaths    = regexp.MustCompile(`(?i)c:\\`)
	reURLs     = regexp.MustCompile(`(?i)https?://`)
	reRegistry = regexp.MustCompile(`HKEY_`)
	reMZ       = regexp.MustCompile(`MZ`)
)

// ErrNotPE: the data is not a PE file the extractor can read.
var ErrNotPE = errors.New("not a PE file")

// IsPE: an MZ header pointing to a PE signature.
func IsPE(b []byte) bool {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(b[0x3c:]))
	return off > 0 && off+4 <= len(b) && bytes.Equal(b[off:off+4], []byte("PE\x00\x00"))
}

func histogram(b []byte) (h [256]float64) {
	for _, c := range b {
		h[c]++
	}
	return
}

// byteEntropy is EMBER's ByteEntropyHistogram(step=1024, window=2048).
func byteEntropy(b []byte) (out [256]float64) {
	const window, step = 2048, 1024
	block := func(blk []byte) {
		var c [16]float64
		for _, x := range blk {
			c[x>>4]++
		}
		h := 0.0
		for _, n := range c {
			if n > 0 {
				p := n / window
				h -= p * math.Log2(p)
			}
		}
		h *= 2
		bin := int(h * 2)
		if bin >= 16 {
			bin = 15
		}
		for i, n := range c {
			out[bin*16+i] += n
		}
	}
	if len(b) < window {
		block(b)
		return
	}
	for start := 0; start+window <= len(b); start += step {
		block(b[start : start+window])
	}
	return
}

func stringFeatures(b []byte) Strings {
	var s Strings
	all := reStrings.FindAll(b, -1)
	s.NumStrings = float64(len(all))
	if len(all) > 0 {
		total := 0
		for _, x := range all {
			total += len(x)
			for _, c := range x {
				s.PrintableDist[c-0x20]++
			}
		}
		s.AvLength = float64(total) / float64(len(all))
		s.Printables = float64(total)
		for _, n := range s.PrintableDist {
			if n > 0 {
				p := n / s.Printables
				s.Entropy -= p * math.Log2(p)
			}
		}
	}
	s.Paths = float64(len(rePaths.FindAll(b, -1)))
	s.URLs = float64(len(reURLs.FindAll(b, -1)))
	s.Registry = float64(len(reRegistry.FindAll(b, -1)))
	s.MZ = float64(len(reMZ.FindAll(b, -1)))
	return s
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var c [256]float64
	for _, x := range b {
		c[x]++
	}
	h := 0.0
	for _, n := range c {
		if n > 0 {
			p := n / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}

var machineNames = map[uint16]string{
	0x14c: "I386", 0x8664: "AMD64", 0x1c0: "ARM", 0x1c4: "ARMNT", 0x200: "IA64",
	0x0: "UNKNOWN", 0x1d3: "AM33", 0xebc: "EBC", 0x9041: "M32R", 0x266: "MIPS16", 0x366: "MIPSFPU",
	0x466: "MIPSFPU16", 0x1f0: "POWERPC", 0x1f1: "POWERPCFP", 0x166: "R4000", 0x1a2: "SH3", 0x1a3: "SH3DSP",
	0x1a6: "SH4", 0x1a8: "SH5", 0x1c2: "THUMB", 0x169: "WCEMIPSV2",
}

var characteristicNames = []struct {
	bit  uint16
	name string
}{
	{0x0001, "RELOCS_STRIPPED"}, {0x0002, "EXECUTABLE_IMAGE"}, {0x0004, "LINE_NUMS_STRIPPED"},
	{0x0008, "LOCAL_SYMS_STRIPPED"}, {0x0010, "AGGRESSIVE_WS_TRIM"}, {0x0020, "LARGE_ADDRESS_AWARE"},
	{0x0080, "BYTES_REVERSED_LO"}, {0x0100, "CHARA_32BIT_MACHINE"}, {0x0200, "DEBUG_STRIPPED"},
	{0x0400, "REMOVABLE_RUN_FROM_SWAP"}, {0x0800, "NET_RUN_FROM_SWAP"}, {0x1000, "SYSTEM"}, {0x2000, "DLL"},
	{0x4000, "UP_SYSTEM_ONLY"}, {0x8000, "BYTES_REVERSED_HI"},
}

var dllCharacteristicNames = []struct {
	bit  uint16
	name string
}{
	{0x0020, "HIGH_ENTROPY_VA"}, {0x0040, "DYNAMIC_BASE"}, {0x0080, "FORCE_INTEGRITY"}, {0x0100, "NX_COMPAT"},
	{0x0200, "NO_ISOLATION"}, {0x0400, "NO_SEH"}, {0x0800, "NO_BIND"}, {0x1000, "APPCONTAINER"},
	{0x2000, "WDM_DRIVER"}, {0x4000, "GUARD_CF"}, {0x8000, "TERMINAL_SERVER_AWARE"},
}

var subsystemNames = map[uint16]string{
	0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
	8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
	12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}

var sectionFlagNames = []struct {
	bit  uint32
	name string
}{
	{0x00000008, "TYPE_NO_PAD"}, {0x00000020, "CNT_CODE"}, {0x00000040, "CNT_INITIALIZED_DATA"},
	{0x00000080, "CNT_UNINITIALIZED_DATA"}, {0x00000100, "LNK_OTHER"}, {0x00000200, "LNK_INFO"},
	{0x00000800, "LNK_REMOVE"}, {0x00001000, "LNK_COMDAT"}, {0x00008000, "GPREL"},
	{0x01000000, "LNK_NRELOC_OVFL"}, {0x02000000, "MEM_DISCARDABLE"}, {0x04000000, "MEM_NOT_CACHED"},
	{0x08000000, "MEM_NOT_PAGED"}, {0x10000000, "MEM_SHARED"}, {0x20000000, "MEM_EXECUTE"},
	{0x40000000, "MEM_READ"}, {0x80000000, "MEM_WRITE"},
}

var alignNames = map[uint32]string{
	1: "ALIGN_1BYTES", 2: "ALIGN_2BYTES", 3: "ALIGN_4BYTES", 4: "ALIGN_8BYTES", 5: "ALIGN_16BYTES",
	6: "ALIGN_32BYTES", 7: "ALIGN_64BYTES", 8: "ALIGN_128BYTES", 9: "ALIGN_256BYTES", 10: "ALIGN_512BYTES",
	11: "ALIGN_1024BYTES", 12: "ALIGN_2048BYTES", 13: "ALIGN_4096BYTES", 14: "ALIGN_8192BYTES",
}

func sectionProps(ch uint32) []string {
	var out []string
	for _, f := range sectionFlagNames {
		if ch&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	if a, ok := alignNames[(ch>>20)&0xf]; ok {
		out = append(out, a)
	}
	return out
}

// ExtractPE computes the raw features of a PE file.
func ExtractPE(b []byte) (*Raw, error) {
	if !IsPE(b) {
		return nil, ErrNotPE
	}
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		// debug/pe refuses a COFF symbol table pointing past the end of the
		// file, which packed and obfuscated programs (Go ones especially)
		// have; LIEF, which EMBER used, ignores it. Parse a copy without it.
		f, err = pe.NewFile(bytes.NewReader(withoutSymbolTable(b)))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotPE, err)
		}
	}
	defer f.Close()
	r := &Raw{Histogram: histogram(b), ByteEntropy: byteEntropy(b), Strings: stringFeatures(b)}

	var dirs []pe.DataDirectory
	var entry, imageBase uint64
	var opt struct {
		magic                                        string
		subsystem, dllChars                          uint16
		majImg, minImg, majOS, minOS, majSub, minSub uint16
		majLink, minLink                             uint8
		sizeCode, sizeHeaders, sizeImage             uint32
		heapCommit                                   uint64
	}
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dirs, entry, imageBase = h.DataDirectory[:h.NumberOfRvaAndSizes], uint64(h.AddressOfEntryPoint), uint64(h.ImageBase)
		opt.magic, opt.subsystem, opt.dllChars = "PE32", h.Subsystem, h.DllCharacteristics
		opt.majImg, opt.minImg, opt.majOS, opt.minOS = h.MajorImageVersion, h.MinorImageVersion, h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion
		opt.majSub, opt.minSub, opt.majLink, opt.minLink = h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.MajorLinkerVersion, h.MinorLinkerVersion
		opt.sizeCode, opt.sizeHeaders, opt.sizeImage, opt.heapCommit = h.SizeOfCode, h.SizeOfHeaders, h.SizeOfImage, uint64(h.SizeOfHeapCommit)
	case *pe.OptionalHeader64:
		dirs, entry, imageBase = h.DataDirectory[:h.NumberOfRvaAndSizes], uint64(h.AddressOfEntryPoint), h.ImageBase
		opt.magic, opt.subsystem, opt.dllChars = "PE32_PLUS", h.Subsystem, h.DllCharacteristics
		opt.majImg, opt.minImg, opt.majOS, opt.minOS = h.MajorImageVersion, h.MinorImageVersion, h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion
		opt.majSub, opt.minSub, opt.majLink, opt.minLink = h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.MajorLinkerVersion, h.MinorLinkerVersion
		opt.sizeCode, opt.sizeHeaders, opt.sizeImage, opt.heapCommit = h.SizeOfCode, h.SizeOfHeaders, h.SizeOfImage, h.SizeOfHeapCommit
	default:
		return nil, ErrNotPE
	}
	_ = imageBase
	dir := func(i int) pe.DataDirectory {
		if i < len(dirs) {
			return dirs[i]
		}
		return pe.DataDirectory{}
	}
	for i := 0; i < 15; i++ {
		d := dir(i)
		r.DataDirs[i] = [2]float64{float64(d.Size), float64(d.VirtualAddress)}
	}

	// header
	r.Header.Timestamp = float64(f.TimeDateStamp)
	r.Header.Machine = machineNames[f.Machine]
	if r.Header.Machine == "" {
		r.Header.Machine = "???" // what EMBER's LIEF wrote for machines it did not know (ARM64 among them)
	}
	for _, c := range characteristicNames {
		if f.Characteristics&c.bit != 0 {
			r.Header.Characteristics = append(r.Header.Characteristics, c.name)
		}
	}
	r.Header.Subsystem = subsystemNames[opt.subsystem]
	if r.Header.Subsystem == "" {
		r.Header.Subsystem = "UNKNOWN"
	}
	for _, c := range dllCharacteristicNames {
		if opt.dllChars&c.bit != 0 {
			r.Header.DllCharacteristics = append(r.Header.DllCharacteristics, c.name)
		}
	}
	r.Header.Magic = opt.magic
	r.Header.Numbers = [11]float64{float64(opt.majImg), float64(opt.minImg), float64(opt.majLink), float64(opt.minLink),
		float64(opt.majOS), float64(opt.minOS), float64(opt.majSub), float64(opt.minSub),
		float64(opt.sizeCode), float64(opt.sizeHeaders), float64(opt.heapCommit)}

	// sections; the entry point's, else the first executable one
	var firstExec string
	rawNames := sectionHeaderNames(b, len(f.Sections))
	for i, s := range f.Sections {
		data, _ := s.Data()
		// LIEF (and so EMBER) reads a section's content up to its virtual size
		if s.VirtualSize > 0 && int(s.VirtualSize) < len(data) {
			data = data[:s.VirtualSize]
		}
		props := sectionProps(s.Characteristics)
		// the header's own 8 bytes ("/4" for a long name), as LIEF reports it
		name := strings.TrimRight(s.Name, "\x00")
		if i < len(rawNames) {
			name = rawNames[i]
		}
		r.Section.List = append(r.Section.List, Section{Name: name, Size: float64(s.Size), Entropy: shannon(data),
			VSize: float64(s.VirtualSize), Props: props})
		if r.Section.Entry == "" && uint64(s.VirtualAddress) <= entry && entry < uint64(s.VirtualAddress)+uint64(max(s.VirtualSize, s.Size)) {
			r.Section.Entry = name
		}
		if firstExec == "" && s.Characteristics&0x20000000 != 0 {
			firstExec = name
		}
	}
	if r.Section.Entry == "" {
		r.Section.Entry = firstExec
	}

	// imports (named; Go's debug/pe leaves out ordinal imports), exports
	r.Imports = map[string][]string{}
	nImports := 0
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			fn, lib, ok := strings.Cut(s, ":")
			if !ok {
				continue
			}
			r.Imports[lib] = append(r.Imports[lib], fn)
			nImports++
		}
	}
	r.Exports = exports(f, b, dir(0))

	g := &r.General
	g.Size = float64(len(b))
	g.VSize = float64(opt.sizeImage)
	g.HasDebug = boolf(dir(6).Size > 0)
	g.Exports = float64(len(r.Exports))
	g.Imports = float64(nImports)
	g.HasRelocations = boolf(dir(5).Size > 0)
	g.HasResources = boolf(dir(2).Size > 0)
	g.HasSignature = boolf(dir(4).Size > 0)
	g.HasTLS = boolf(dir(9).Size > 0)
	if o := peOffset(b) + 4 + 12; o+4 <= len(b) {
		g.Symbols = float64(binary.LittleEndian.Uint32(b[o:])) // the header's, even when parsed without it
	}
	return r, nil
}

// sectionHeaderNames reads each section header's 8-byte name as stored
// (debug/pe resolves "/4" long names through the COFF string table).
func peOffset(b []byte) int { return int(binary.LittleEndian.Uint32(b[0x3c:])) }

// withoutSymbolTable: a copy of b with the COFF header's symbol table pointer
// and count zeroed (b passed IsPE, so the header is inside b).
func withoutSymbolTable(b []byte) []byte {
	c := append([]byte(nil), b...)
	coff := peOffset(c) + 4
	if coff+20 <= len(c) {
		binary.LittleEndian.PutUint32(c[coff+8:], 0)
		binary.LittleEndian.PutUint32(c[coff+12:], 0)
	}
	return c
}

func sectionHeaderNames(b []byte, n int) []string {
	pe := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if pe+24 > len(b) {
		return nil
	}
	optSize := int(binary.LittleEndian.Uint16(b[pe+20:]))
	at := pe + 24 + optSize
	var out []string
	for i := 0; i < n && at+40*i+8 <= len(b); i++ {
		out = append(out, strings.TrimRight(string(b[at+40*i:at+40*i+8]), "\x00"))
	}
	return out
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// exports reads the export directory's names.
func exports(f *pe.File, b []byte, d pe.DataDirectory) []string {
	if d.Size == 0 || d.VirtualAddress == 0 {
		return nil
	}
	off, ok := rvaToOffset(f, d.VirtualAddress)
	if !ok || off+40 > len(b) {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b[off+24:]))
	namesRVA := binary.LittleEndian.Uint32(b[off+32:])
	tbl, ok := rvaToOffset(f, namesRVA)
	if !ok || n > 65536 {
		return nil
	}
	var out []string
	for i := 0; i < n && tbl+4*i+4 <= len(b); i++ {
		nameOff, ok := rvaToOffset(f, binary.LittleEndian.Uint32(b[tbl+4*i:]))
		if !ok || nameOff >= len(b) {
			continue
		}
		end := bytes.IndexByte(b[nameOff:], 0)
		if end < 0 || end > 512 {
			continue
		}
		out = append(out, string(b[nameOff:nameOff+end]))
	}
	return out
}

func rvaToOffset(f *pe.File, rva uint32) (int, bool) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			return int(rva - s.VirtualAddress + s.Offset), true
		}
	}
	return 0, false
}
