package yara

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// The pe module follows libyara's field names and semantics for the
// fields it declares. Not implemented (compile errors if used):
// signatures/authenticode, rich_signature, resources, version_info,
// delayed imports.

const (
	maxPESections = 96
	maxPEImports  = 16384
	maxPEExports  = 16384
)

type peSection struct {
	name                       string
	va, vsize, rawOff, rawSize uint32
	relocPtr, linePtr          uint32
	nRelocs, nLines            uint16
	chars                      uint32
}

type peImport struct {
	dll   string
	funcs []peFunc
}

type peFunc struct {
	name    string
	ordinal int64 // -1 when imported by name
	rva     int64
}

type peExport struct {
	name, forward string
	ordinal       int64
	rva           int64
	offset        int64
}

type peFile struct {
	data     []byte
	is64     bool
	opt      int // optional header offset
	fileAlig uint32
	nsecs    int
	secs     []peSection
	imports  []peImport
	exports  []peExport
	chars    uint16
	dllName  string
}

func (p *peFile) u16(off int) (uint16, bool) {
	if off < 0 || off+2 > len(p.data) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(p.data[off:]), true
}

func (p *peFile) u32(off int) (uint32, bool) {
	if off < 0 || off+4 > len(p.data) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p.data[off:]), true
}

func (p *peFile) u64(off int) (uint64, bool) {
	if off < 0 || off+8 > len(p.data) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(p.data[off:]), true
}

// cstr reads a NUL-terminated string at off, up to max bytes.
func (p *peFile) cstr(off int64, max int) (string, bool) {
	if off < 0 || off >= int64(len(p.data)) {
		return "", false
	}
	b := p.data[off:]
	if len(b) > max {
		b = b[:max]
	}
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", false
	}
	return string(b[:i]), true
}

// rvaToOffset is libyara's pe_rva_to_offset.
func (p *peFile) rvaToOffset(rva uint64) int64 {
	lowest := uint64(0xffffffff)
	var secRVA, secOff, secRaw int64
	n := min(p.nsecs, 60)
	for i := 0; i < n && i < len(p.secs); i++ {
		s := p.secs[i]
		if lowest > uint64(s.va) {
			lowest = uint64(s.va)
		}
		if rva >= uint64(s.va) && secRVA <= int64(s.va) {
			align := int64(min(p.fileAlig, 0x200))
			secRVA, secOff, secRaw = int64(s.va), int64(s.rawOff), int64(s.rawSize)
			if align != 0 {
				secOff = secOff / align * align
			}
		}
	}
	if rva < lowest {
		secRVA, secOff, secRaw = 0, 0, int64(len(p.data))
	}
	if int64(rva)-secRVA >= secRaw {
		return -1
	}
	res := secOff + (int64(rva) - secRVA)
	if res >= int64(len(p.data)) {
		return -1
	}
	return res
}

func parsePE(data []byte) *peFile {
	p := &peFile{data: data}
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil
	}
	lfanew, _ := p.u32(0x3c)
	h := int(lfanew)
	if h < 0 || h+24 > len(data) || !bytes.Equal(data[h:h+4], []byte("PE\x00\x00")) {
		return nil
	}
	p.opt = h + 24
	magic, ok := p.u16(p.opt)
	if !ok {
		return nil
	}
	p.is64 = magic == 0x20b
	optSize, _ := p.u16(h + 20)
	nsecs, _ := p.u16(h + 6)
	p.nsecs = int(nsecs)
	p.chars, _ = p.u16(h + 22)
	p.fileAlig, _ = p.u32(p.opt + 36)
	secTable := p.opt + int(optSize)
	for i := 0; i < min(p.nsecs, maxPESections); i++ {
		o := secTable + i*40
		if o+40 > len(data) {
			break
		}
		raw := data[o : o+8]
		if j := bytes.IndexByte(raw, 0); j >= 0 {
			raw = raw[:j]
		}
		le := binary.LittleEndian
		p.secs = append(p.secs, peSection{
			name:     string(raw),
			vsize:    le.Uint32(data[o+8:]),
			va:       le.Uint32(data[o+12:]),
			rawSize:  le.Uint32(data[o+16:]),
			rawOff:   le.Uint32(data[o+20:]),
			relocPtr: le.Uint32(data[o+24:]),
			linePtr:  le.Uint32(data[o+28:]),
			nRelocs:  le.Uint16(data[o+32:]),
			nLines:   le.Uint16(data[o+34:]),
			chars:    le.Uint32(data[o+36:]),
		})
	}
	p.parseImports()
	p.parseExports()
	return p
}

func (p *peFile) dataDirOffset() int {
	if p.is64 {
		return p.opt + 112
	}
	return p.opt + 96
}

func (p *peFile) numDirs() uint32 {
	o := p.opt + 92
	if p.is64 {
		o = p.opt + 108
	}
	n, _ := p.u32(o)
	return n
}

func (p *peFile) dir(i int) (rva, size uint32, ok bool) {
	if uint32(i) >= p.numDirs() {
		return 0, 0, false
	}
	o := p.dataDirOffset() + i*8
	rva, ok1 := p.u32(o)
	size, ok2 := p.u32(o + 4)
	return rva, size, ok1 && ok2
}

func validDLLName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '*' || c == '<' || c == '>' || c == '?' || c == '|' {
			return false
		}
	}
	return true
}

func (p *peFile) parseImports() {
	rva, _, ok := p.dir(1)
	if !ok || rva == 0 {
		return
	}
	off := p.rvaToOffset(uint64(rva))
	if off < 0 {
		return
	}
	total := 0
	for d := int(off); d+20 <= len(p.data); d += 20 {
		oft, _ := p.u32(d)
		nameRVA, _ := p.u32(d + 12)
		ft, _ := p.u32(d + 16)
		if nameRVA == 0 {
			break
		}
		name, ok := p.cstr(p.rvaToOffset(uint64(nameRVA)), 256)
		if !ok || !validDLLName(name) {
			continue
		}
		thunks := oft
		if thunks == 0 {
			thunks = ft
		}
		imp := peImport{dll: name}
		toff := p.rvaToOffset(uint64(thunks))
		step := 4
		if p.is64 {
			step = 8
		}
		for i := 0; toff >= 0 && total < maxPEImports; i++ {
			var v uint64
			var ok bool
			if p.is64 {
				v, ok = p.u64(int(toff) + i*step)
			} else {
				var v32 uint32
				v32, ok = p.u32(int(toff) + i*step)
				v = uint64(v32)
			}
			if !ok || v == 0 {
				break
			}
			f := peFunc{ordinal: -1, rva: int64(ft) + int64(i*step)}
			ordFlag := uint64(0x80000000)
			if p.is64 {
				ordFlag = 0x8000000000000000
			}
			if v&ordFlag != 0 {
				f.ordinal = int64(v & 0xffff)
			} else {
				fname, ok := p.cstr(p.rvaToOffset(v&0x7fffffff)+2, 512)
				if !ok {
					continue
				}
				f.name = fname
			}
			imp.funcs = append(imp.funcs, f)
			total++
		}
		p.imports = append(p.imports, imp)
	}
}

func (p *peFile) parseExports() {
	rva, size, ok := p.dir(0)
	if !ok || rva == 0 {
		return
	}
	off := p.rvaToOffset(uint64(rva))
	if off < 0 || int(off)+40 > len(p.data) {
		return
	}
	o := int(off)
	nameRVA, _ := p.u32(o + 12)
	base, _ := p.u32(o + 16)
	nFuncs, _ := p.u32(o + 20)
	nNames, _ := p.u32(o + 24)
	funcsRVA, _ := p.u32(o + 28)
	namesRVA, _ := p.u32(o + 32)
	ordsRVA, _ := p.u32(o + 36)
	if s, ok := p.cstr(p.rvaToOffset(uint64(nameRVA)), 256); ok {
		p.dllName = s
	}
	funcsOff := p.rvaToOffset(uint64(funcsRVA))
	if funcsOff < 0 {
		return
	}
	n := min(int(nFuncs), maxPEExports)
	names := map[int]string{}
	namesOff, ordsOff := p.rvaToOffset(uint64(namesRVA)), p.rvaToOffset(uint64(ordsRVA))
	if namesOff >= 0 && ordsOff >= 0 {
		for i := 0; i < min(int(nNames), maxPEExports); i++ {
			nr, ok1 := p.u32(int(namesOff) + i*4)
			idx, ok2 := p.u16(int(ordsOff) + i*2)
			if !ok1 || !ok2 {
				break
			}
			if s, ok := p.cstr(p.rvaToOffset(uint64(nr)), 512); ok {
				names[int(idx)] = s
			}
		}
	}
	for i := 0; i < n; i++ {
		fr, ok := p.u32(int(funcsOff) + i*4)
		if !ok {
			break
		}
		e := peExport{name: names[i], ordinal: int64(base) + int64(i), rva: int64(fr), offset: p.rvaToOffset(uint64(fr))}
		if fr >= rva && fr < rva+size {
			e.forward, _ = p.cstr(e.offset, 256)
		}
		p.exports = append(p.exports, e)
	}
}

// imphash follows pefile/libyara, except that ordinal imports are not
// resolved to names; the hash is undefined when one exists.
func (p *peFile) imphash() value {
	var parts []string
	for _, imp := range p.imports {
		dll := strings.ToLower(imp.dll)
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			if strings.HasSuffix(dll, ext) {
				dll = dll[:len(dll)-len(ext)]
				break
			}
		}
		for _, f := range imp.funcs {
			if f.ordinal >= 0 {
				return undef
			}
			parts = append(parts, dll+"."+strings.ToLower(f.name))
		}
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return vStr(hex.EncodeToString(sum[:]))
}

func (p *peFile) value() value {
	m := map[string]value{"is_pe": vInt(1)}
	h := p.opt - 24
	le := func(o, size int) value {
		switch size {
		case 1:
			if o < len(p.data) {
				return vInt(int64(p.data[o]))
			}
		case 2:
			if v, ok := p.u16(o); ok {
				return vInt(int64(v))
			}
		case 4:
			if v, ok := p.u32(o); ok {
				return vInt(int64(v))
			}
		case 8:
			if v, ok := p.u64(o); ok {
				return vInt(int64(v))
			}
		}
		return undef
	}
	m["machine"] = le(h+4, 2)
	m["number_of_sections"] = le(h+6, 2)
	m["timestamp"] = le(h+8, 4)
	m["pointer_to_symbol_table"] = le(h+12, 4)
	m["number_of_symbols"] = le(h+16, 4)
	m["size_of_optional_header"] = le(h+20, 2)
	m["characteristics"] = le(h+22, 2)
	o := p.opt
	m["opthdr_magic"] = le(o, 2)
	m["linker_version"] = value{k: tyStruct, m: map[string]value{"major": le(o+2, 1), "minor": le(o+3, 1)}}
	m["size_of_code"] = le(o+4, 4)
	m["size_of_initialized_data"] = le(o+8, 4)
	m["size_of_uninitialized_data"] = le(o+12, 4)
	m["entry_point_raw"] = le(o+16, 4)
	if ep, ok := p.u32(o + 16); ok {
		if off := p.rvaToOffset(uint64(ep)); off >= 0 {
			m["entry_point"] = vInt(off)
		}
	}
	m["base_of_code"] = le(o+20, 4)
	ptr := 8
	if !p.is64 {
		m["base_of_data"] = le(o+24, 4)
		m["image_base"] = le(o+28, 4)
		ptr = 4
	} else {
		m["image_base"] = le(o+24, 8)
	}
	m["section_alignment"] = le(o+32, 4)
	m["file_alignment"] = le(o+36, 4)
	m["os_version"] = value{k: tyStruct, m: map[string]value{"major": le(o+40, 2), "minor": le(o+42, 2)}}
	m["image_version"] = value{k: tyStruct, m: map[string]value{"major": le(o+44, 2), "minor": le(o+46, 2)}}
	m["subsystem_version"] = value{k: tyStruct, m: map[string]value{"major": le(o+48, 2), "minor": le(o+50, 2)}}
	m["win32_version_value"] = le(o+52, 4)
	m["size_of_image"] = le(o+56, 4)
	m["size_of_headers"] = le(o+60, 4)
	m["checksum"] = le(o+64, 4)
	m["subsystem"] = le(o+68, 2)
	m["dll_characteristics"] = le(o+70, 2)
	m["size_of_stack_reserve"] = le(o+72, ptr)
	m["size_of_stack_commit"] = le(o+72+ptr, ptr)
	m["size_of_heap_reserve"] = le(o+72+2*ptr, ptr)
	m["size_of_heap_commit"] = le(o+72+3*ptr, ptr)
	m["loader_flags"] = le(o+72+4*ptr, 4)
	m["number_of_rva_and_sizes"] = le(o+76+4*ptr, 4)

	var dirs []value
	for i := 0; i < int(min(p.numDirs(), 16)); i++ {
		rva, size, ok := p.dir(i)
		if !ok {
			break
		}
		dirs = append(dirs, value{k: tyStruct, m: map[string]value{"virtual_address": vInt(int64(rva)), "size": vInt(int64(size))}})
	}
	m["data_directories"] = value{k: tyArray, a: dirs}

	var secs []value
	lastEnd := int64(0)
	for _, s := range p.secs {
		secs = append(secs, value{k: tyStruct, m: map[string]value{
			"name": vStr(s.name), "full_name": vStr(s.name),
			"characteristics": vInt(int64(s.chars)),
			"virtual_address": vInt(int64(s.va)), "virtual_size": vInt(int64(s.vsize)),
			"raw_data_offset": vInt(int64(s.rawOff)), "raw_data_size": vInt(int64(s.rawSize)),
			"pointer_to_relocations": vInt(int64(s.relocPtr)), "pointer_to_line_numbers": vInt(int64(s.linePtr)),
			"number_of_relocations": vInt(int64(s.nRelocs)), "number_of_line_numbers": vInt(int64(s.nLines)),
		}})
		lastEnd = max(lastEnd, int64(s.rawOff)+int64(s.rawSize))
	}
	m["sections"] = value{k: tyArray, a: secs}
	if lastEnd < int64(len(p.data)) && len(p.secs) > 0 {
		m["overlay"] = value{k: tyStruct, m: map[string]value{"offset": vInt(lastEnd), "size": vInt(int64(len(p.data)) - lastEnd)}}
	} else {
		m["overlay"] = value{k: tyStruct, m: map[string]value{"offset": vInt(0), "size": vInt(0)}}
	}

	nfuncs := 0
	var imps []value
	for _, imp := range p.imports {
		var fs []value
		for _, f := range imp.funcs {
			fv := map[string]value{"rva": vInt(f.rva)}
			if f.ordinal >= 0 {
				fv["ordinal"] = vInt(f.ordinal)
			} else {
				fv["name"] = vStr(f.name)
			}
			fs = append(fs, value{k: tyStruct, m: fv})
		}
		nfuncs += len(imp.funcs)
		imps = append(imps, value{k: tyStruct, m: map[string]value{
			"library_name": vStr(imp.dll), "number_of_functions": vInt(int64(len(imp.funcs))),
			"functions": {k: tyArray, a: fs},
		}})
	}
	m["number_of_imports"] = vInt(int64(len(p.imports)))
	m["number_of_imported_functions"] = vInt(int64(nfuncs))
	m["import_details"] = value{k: tyArray, a: imps}

	var exps []value
	for _, e := range p.exports {
		ev := map[string]value{"ordinal": vInt(e.ordinal), "rva": vInt(e.rva)}
		if e.name != "" {
			ev["name"] = vStr(e.name)
		}
		if e.forward != "" {
			ev["forward_name"] = vStr(e.forward)
		} else if e.offset >= 0 {
			ev["offset"] = vInt(e.offset)
		}
		exps = append(exps, value{k: tyStruct, m: ev})
	}
	m["number_of_exports"] = vInt(int64(len(p.exports)))
	m["export_details"] = value{k: tyArray, a: exps}
	if p.dllName != "" {
		m["dll_name"] = vStr(p.dllName)
	}
	if rva, _, ok := p.dir(0); ok && rva != 0 {
		if off := p.rvaToOffset(uint64(rva)); off >= 0 {
			m["export_timestamp"] = le(int(off)+4, 4)
		}
	}
	if path, ok := p.pdbPath(); ok {
		m["pdb_path"] = vStr(path)
	}
	return value{k: tyStruct, m: m}
}

// pdbPath reads the CodeView record of the debug directory.
func (p *peFile) pdbPath() (string, bool) {
	rva, size, ok := p.dir(6)
	if !ok || rva == 0 {
		return "", false
	}
	off := p.rvaToOffset(uint64(rva))
	if off < 0 {
		return "", false
	}
	for i := 0; i < int(size/28) && i < 16; i++ {
		e := int(off) + i*28
		typ, ok := p.u32(e + 12)
		if !ok {
			break
		}
		if typ != 2 { // IMAGE_DEBUG_TYPE_CODEVIEW
			continue
		}
		addr, _ := p.u32(e + 20)
		ptr, _ := p.u32(e + 24)
		cv := int64(ptr)
		if addr != 0 {
			cv = p.rvaToOffset(uint64(addr))
		}
		if cv < 0 || cv+4 > int64(len(p.data)) {
			continue
		}
		switch string(p.data[cv : cv+4]) {
		case "RSDS":
			return p.cstr(cv+24, 1024)
		case "NB10":
			return p.cstr(cv+16, 1024)
		}
	}
	return "", false
}

func peState(state any) *peFile {
	p, _ := state.(*peFile)
	return p
}

func init() {
	k := sConst
	consts := map[string]int64{
		"MACHINE_UNKNOWN": 0x0, "MACHINE_AM33": 0x1d3, "MACHINE_AMD64": 0x8664, "MACHINE_ARM": 0x1c0,
		"MACHINE_ARMNT": 0x1c4, "MACHINE_ARM64": 0xaa64, "MACHINE_EBC": 0xebc, "MACHINE_I386": 0x14c,
		"MACHINE_IA64": 0x200, "MACHINE_M32R": 0x9041, "MACHINE_MIPS16": 0x266, "MACHINE_MIPSFPU": 0x366,
		"MACHINE_MIPSFPU16": 0x466, "MACHINE_POWERPC": 0x1f0, "MACHINE_POWERPCFP": 0x1f1, "MACHINE_R4000": 0x166,
		"MACHINE_SH3": 0x1a2, "MACHINE_SH3DSP": 0x1a3, "MACHINE_SH4": 0x1a6, "MACHINE_SH5": 0x1a8,
		"MACHINE_THUMB": 0x1c2, "MACHINE_WCEMIPSV2": 0x169, "MACHINE_RISCV32": 0x5032, "MACHINE_RISCV64": 0x5064,
		"SUBSYSTEM_UNKNOWN": 0, "SUBSYSTEM_NATIVE": 1, "SUBSYSTEM_WINDOWS_GUI": 2, "SUBSYSTEM_WINDOWS_CUI": 3,
		"SUBSYSTEM_OS2_CUI": 5, "SUBSYSTEM_POSIX_CUI": 7, "SUBSYSTEM_NATIVE_WINDOWS": 8, "SUBSYSTEM_WINDOWS_CE_GUI": 9,
		"SUBSYSTEM_EFI_APPLICATION": 10, "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": 11, "SUBSYSTEM_EFI_RUNTIME_DRIVER": 12,
		"SUBSYSTEM_EFI_ROM_IMAGE": 13, "SUBSYSTEM_XBOX": 14, "SUBSYSTEM_WINDOWS_BOOT_APPLICATION": 16,
		"RELOCS_STRIPPED": 0x1, "EXECUTABLE_IMAGE": 0x2, "LINE_NUMS_STRIPPED": 0x4, "LOCAL_SYMS_STRIPPED": 0x8,
		"AGGRESIVE_WS_TRIM": 0x10, "LARGE_ADDRESS_AWARE": 0x20, "BYTES_REVERSED_LO": 0x80, "MACHINE_32BIT": 0x100,
		"DEBUG_STRIPPED": 0x200, "REMOVABLE_RUN_FROM_SWAP": 0x400, "NET_RUN_FROM_SWAP": 0x800, "SYSTEM": 0x1000,
		"DLL": 0x2000, "UP_SYSTEM_ONLY": 0x4000, "BYTES_REVERSED_HI": 0x8000,
		"HIGH_ENTROPY_VA": 0x20, "DYNAMIC_BASE": 0x40, "FORCE_INTEGRITY": 0x80, "NX_COMPAT": 0x100,
		"NO_ISOLATION": 0x200, "NO_SEH": 0x400, "NO_BIND": 0x800, "APPCONTAINER": 0x1000, "WDM_DRIVER": 0x2000,
		"GUARD_CF": 0x4000, "TERMINAL_SERVER_AWARE": 0x8000,
		"SECTION_NO_PAD": 0x8, "SECTION_CNT_CODE": 0x20, "SECTION_CNT_INITIALIZED_DATA": 0x40,
		"SECTION_CNT_UNINITIALIZED_DATA": 0x80, "SECTION_LNK_OTHER": 0x100, "SECTION_LNK_INFO": 0x200,
		"SECTION_LNK_REMOVE": 0x800, "SECTION_LNK_COMDAT": 0x1000, "SECTION_NO_DEFER_SPEC_EXC": 0x4000,
		"SECTION_GPREL": 0x8000, "SECTION_MEM_PURGEABLE": 0x20000, "SECTION_MEM_LOCKED": 0x40000,
		"SECTION_MEM_PRELOAD": 0x80000, "SECTION_LNK_NRELOC_OVFL": 0x1000000, "SECTION_MEM_DISCARDABLE": 0x2000000,
		"SECTION_MEM_NOT_CACHED": 0x4000000, "SECTION_MEM_NOT_PAGED": 0x8000000, "SECTION_MEM_SHARED": 0x10000000,
		"SECTION_MEM_EXECUTE": 0x20000000, "SECTION_MEM_READ": 0x40000000, "SECTION_MEM_WRITE": 0x80000000,
		"IMAGE_DIRECTORY_ENTRY_EXPORT": 0, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1, "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2,
		"IMAGE_DIRECTORY_ENTRY_EXCEPTION": 3, "IMAGE_DIRECTORY_ENTRY_SECURITY": 4, "IMAGE_DIRECTORY_ENTRY_BASERELOC": 5,
		"IMAGE_DIRECTORY_ENTRY_DEBUG": 6, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE": 7, "IMAGE_DIRECTORY_ENTRY_COPYRIGHT": 7,
		"IMAGE_DIRECTORY_ENTRY_GLOBALPTR": 8, "IMAGE_DIRECTORY_ENTRY_TLS": 9, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": 10,
		"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": 11, "IMAGE_DIRECTORY_ENTRY_IAT": 12, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": 13,
		"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": 14,
		"IMAGE_NT_OPTIONAL_HDR32_MAGIC":        0x10b, "IMAGE_NT_OPTIONAL_HDR64_MAGIC": 0x20b, "IMAGE_ROM_OPTIONAL_HDR_MAGIC": 0x107,
	}
	version := func() *schema { return sStruct(map[string]*schema{"major": sInt(), "minor": sInt()}) }
	f := map[string]*schema{
		"is_pe": sInt(), "machine": sInt(), "number_of_sections": sInt(), "timestamp": sInt(),
		"pointer_to_symbol_table": sInt(), "number_of_symbols": sInt(), "size_of_optional_header": sInt(),
		"characteristics": sInt(), "opthdr_magic": sInt(), "linker_version": version(), "size_of_code": sInt(),
		"size_of_initialized_data": sInt(), "size_of_uninitialized_data": sInt(), "entry_point": sInt(),
		"entry_point_raw": sInt(), "base_of_code": sInt(), "base_of_data": sInt(), "image_base": sInt(),
		"section_alignment": sInt(), "file_alignment": sInt(), "os_version": version(), "image_version": version(),
		"subsystem_version": version(), "win32_version_value": sInt(), "size_of_image": sInt(),
		"size_of_headers": sInt(), "checksum": sInt(), "subsystem": sInt(), "dll_characteristics": sInt(),
		"size_of_stack_reserve": sInt(), "size_of_stack_commit": sInt(), "size_of_heap_reserve": sInt(),
		"size_of_heap_commit": sInt(), "loader_flags": sInt(), "number_of_rva_and_sizes": sInt(),
		"data_directories": sArray(sStruct(map[string]*schema{"virtual_address": sInt(), "size": sInt()})),
		"sections": sArray(sStruct(map[string]*schema{
			"name": sStr(), "full_name": sStr(), "characteristics": sInt(), "virtual_address": sInt(),
			"virtual_size": sInt(), "raw_data_offset": sInt(), "raw_data_size": sInt(),
			"pointer_to_relocations": sInt(), "pointer_to_line_numbers": sInt(),
			"number_of_relocations": sInt(), "number_of_line_numbers": sInt(),
		})),
		"overlay":                      sStruct(map[string]*schema{"offset": sInt(), "size": sInt()}),
		"number_of_imports":            sInt(),
		"number_of_imported_functions": sInt(),
		"import_details": sArray(sStruct(map[string]*schema{
			"library_name": sStr(), "number_of_functions": sInt(),
			"functions": sArray(sStruct(map[string]*schema{"name": sStr(), "ordinal": sInt(), "rva": sInt()})),
		})),
		"number_of_exports": sInt(),
		"export_details": sArray(sStruct(map[string]*schema{
			"offset": sInt(), "name": sStr(), "forward_name": sStr(), "ordinal": sInt(), "rva": sInt(),
		})),
		"dll_name":         sStr(),
		"export_timestamp": sInt(),
		"pdb_path":         sStr(),
	}
	for name, v := range consts {
		f[name] = k(v)
	}

	withPE := func(ret vtype, body func(p *peFile, sc *scanCtx, a []value) value, args ...vtype) *overload {
		return fn(ret, func(sc *scanCtx, state any, a []value) value {
			p := peState(state)
			if p == nil {
				return undef
			}
			return body(p, sc, a)
		}, args...)
	}
	countImports := func(p *peFile, match func(dll string, f peFunc) bool) int64 {
		n := int64(0)
		for _, imp := range p.imports {
			for _, fn := range imp.funcs {
				if match(imp.dll, fn) {
					n++
				}
			}
		}
		return n
	}
	f["imports"] = sFunc(
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			return vInt(countImports(p, func(dll string, fn peFunc) bool {
				return strings.EqualFold(dll, a[0].s) && fn.ordinal < 0 && strings.EqualFold(fn.name, a[1].s)
			}))
		}, tyStr, tyStr),
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			return vInt(countImports(p, func(dll string, fn peFunc) bool {
				return strings.EqualFold(dll, a[0].s) && fn.ordinal == a[1].i
			}))
		}, tyStr, tyInt),
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			return vInt(countImports(p, func(dll string, _ peFunc) bool { return strings.EqualFold(dll, a[0].s) }))
		}, tyStr),
	)
	f["exports"] = sFunc(
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for _, e := range p.exports {
				if e.name != "" && strings.EqualFold(e.name, a[0].s) {
					return vInt(1)
				}
			}
			return vInt(0)
		}, tyStr),
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for _, e := range p.exports {
				if e.ordinal == a[0].i {
					return vInt(1)
				}
			}
			return vInt(0)
		}, tyInt),
	)
	f["exports_index"] = sFunc(
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for i, e := range p.exports {
				if e.name != "" && strings.EqualFold(e.name, a[0].s) {
					return vInt(int64(i))
				}
			}
			return undef
		}, tyStr),
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for i, e := range p.exports {
				if e.ordinal == a[0].i {
					return vInt(int64(i))
				}
			}
			return undef
		}, tyInt),
	)
	f["section_index"] = sFunc(
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for i, s := range p.secs {
				if s.name == a[0].s {
					return vInt(int64(i))
				}
			}
			return undef
		}, tyStr),
		withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
			for i, s := range p.secs {
				if a[0].i >= int64(s.rawOff) && a[0].i < int64(s.rawOff)+int64(s.rawSize) {
					return vInt(int64(i))
				}
			}
			return undef
		}, tyInt),
	)
	f["is_dll"] = sFunc(withPE(tyInt, func(p *peFile, _ *scanCtx, _ []value) value {
		return vInt(int64(p.chars&0x2000) >> 13)
	}))
	f["is_32bit"] = sFunc(withPE(tyInt, func(p *peFile, _ *scanCtx, _ []value) value {
		magic, _ := p.u16(p.opt)
		return vBoolInt(magic == 0x10b)
	}))
	f["is_64bit"] = sFunc(withPE(tyInt, func(p *peFile, _ *scanCtx, _ []value) value {
		magic, _ := p.u16(p.opt)
		return vBoolInt(magic == 0x20b)
	}))
	f["imphash"] = sFunc(withPE(tyStr, func(p *peFile, _ *scanCtx, _ []value) value { return p.imphash() }))
	f["rva_to_offset"] = sFunc(withPE(tyInt, func(p *peFile, _ *scanCtx, a []value) value {
		if off := p.rvaToOffset(uint64(a[0].i)); off >= 0 {
			return vInt(off)
		}
		return undef
	}, tyInt))

	registerModule(&module{
		name:   "pe",
		schema: sStruct(f),
		load: func(sc *scanCtx) (value, any) {
			p := parsePE(sc.data)
			if p == nil {
				return value{k: tyStruct, m: map[string]value{"is_pe": vInt(0)}}, nil
			}
			return p.value(), p
		},
	})
}

func vBoolInt(b bool) value {
	if b {
		return vInt(1)
	}
	return vInt(0)
}
