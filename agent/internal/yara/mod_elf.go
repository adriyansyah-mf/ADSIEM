package yara

import (
	"bytes"
	"encoding/binary"
)

// The elf module follows libyara's field names. Not implemented:
// telfhash(), import_md5(), notes.

type elfFile struct {
	data  []byte
	bo    binary.ByteOrder
	is64  bool
	typ   uint16
	entry uint64
	secs  []elfSection
	segs  []elfSegment

	phoff, shoff, phentsize, shentsize uint64
}

type elfSection struct {
	name                      string
	typ                       uint32
	flags, addr, offset, size uint64
	link                      uint32
	entsize                   uint64
}

type elfSegment struct {
	typ, flags                                 uint32
	offset, vaddr, paddr, filesz, memsz, align uint64
}

const maxELFEntries = 65536

func (e *elfFile) uint(off, size int) (uint64, bool) {
	if off < 0 || off+size > len(e.data) {
		return 0, false
	}
	switch size {
	case 1:
		return uint64(e.data[off]), true
	case 2:
		return uint64(e.bo.Uint16(e.data[off:])), true
	case 4:
		return uint64(e.bo.Uint32(e.data[off:])), true
	}
	return e.bo.Uint64(e.data[off:]), true
}

func (e *elfFile) word(off int) (uint64, bool) {
	if e.is64 {
		return e.uint(off, 8)
	}
	return e.uint(off, 4)
}

func (e *elfFile) cstr(off uint64) (string, bool) {
	if off >= uint64(len(e.data)) {
		return "", false
	}
	b := e.data[off:]
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", false
	}
	return string(b[:i]), true
}

func parseELF(data []byte) *elfFile {
	if len(data) < 52 || !bytes.Equal(data[:4], []byte("\x7fELF")) {
		return nil
	}
	e := &elfFile{data: data}
	switch data[4] {
	case 1:
	case 2:
		e.is64 = true
		if len(data) < 64 {
			return nil
		}
	default:
		return nil
	}
	switch data[5] {
	case 1:
		e.bo = binary.LittleEndian
	case 2:
		e.bo = binary.BigEndian
	default:
		return nil
	}
	t, _ := e.uint(16, 2)
	e.typ = uint16(t)
	e.entry, _ = e.word(24)
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum, shstrndx uint64
	defer func() { e.phoff, e.shoff, e.phentsize, e.shentsize = phoff, shoff, phentsize, shentsize }()
	if e.is64 {
		phoff, _ = e.uint(32, 8)
		shoff, _ = e.uint(40, 8)
		phentsize, _ = e.uint(54, 2)
		phnum, _ = e.uint(56, 2)
		shentsize, _ = e.uint(58, 2)
		shnum, _ = e.uint(60, 2)
		shstrndx, _ = e.uint(62, 2)
	} else {
		phoff, _ = e.uint(28, 4)
		shoff, _ = e.uint(32, 4)
		phentsize, _ = e.uint(42, 2)
		phnum, _ = e.uint(44, 2)
		shentsize, _ = e.uint(46, 2)
		shnum, _ = e.uint(48, 2)
		shstrndx, _ = e.uint(50, 2)
	}
	if shoff != 0 && shnum > 0 && shentsize > 0 && shoff+shnum*shentsize <= uint64(len(data)) {
		for i := uint64(0); i < min(shnum, maxELFEntries); i++ {
			o := int(shoff + i*shentsize)
			var s elfSection
			t, _ := e.uint(o+4, 4)
			s.typ = uint32(t)
			if e.is64 {
				s.flags, _ = e.uint(o+8, 8)
				s.addr, _ = e.uint(o+16, 8)
				s.offset, _ = e.uint(o+24, 8)
				s.size, _ = e.uint(o+32, 8)
				l, _ := e.uint(o+40, 4)
				s.link = uint32(l)
				s.entsize, _ = e.uint(o+56, 8)
			} else {
				s.flags, _ = e.uint(o+8, 4)
				s.addr, _ = e.uint(o+12, 4)
				s.offset, _ = e.uint(o+16, 4)
				s.size, _ = e.uint(o+20, 4)
				l, _ := e.uint(o+24, 4)
				s.link = uint32(l)
				s.entsize, _ = e.uint(o+36, 4)
			}
			e.secs = append(e.secs, s)
		}
		// Names come from the section-name string table.
		if shstrndx < uint64(len(e.secs)) && e.secs[shstrndx].typ == 3 {
			strtab := e.secs[shstrndx]
			for i := range e.secs {
				nameOff, _ := e.uint(int(shoff+uint64(i)*shentsize), 4)
				if nameOff < strtab.size {
					e.secs[i].name, _ = e.cstr(strtab.offset + nameOff)
				}
			}
		}
	}
	if phoff != 0 && phnum > 0 && phentsize > 0 && phoff+phnum*phentsize <= uint64(len(data)) {
		for i := uint64(0); i < min(phnum, maxELFEntries); i++ {
			o := int(phoff + i*phentsize)
			var s elfSegment
			t, _ := e.uint(o, 4)
			s.typ = uint32(t)
			if e.is64 {
				f, _ := e.uint(o+4, 4)
				s.flags = uint32(f)
				s.offset, _ = e.uint(o+8, 8)
				s.vaddr, _ = e.uint(o+16, 8)
				s.paddr, _ = e.uint(o+24, 8)
				s.filesz, _ = e.uint(o+32, 8)
				s.memsz, _ = e.uint(o+40, 8)
				s.align, _ = e.uint(o+48, 8)
			} else {
				s.offset, _ = e.uint(o+4, 4)
				s.vaddr, _ = e.uint(o+8, 4)
				s.paddr, _ = e.uint(o+12, 4)
				s.filesz, _ = e.uint(o+16, 4)
				s.memsz, _ = e.uint(o+20, 4)
				f, _ := e.uint(o+24, 4)
				s.flags = uint32(f)
				s.align, _ = e.uint(o+28, 4)
			}
			e.segs = append(e.segs, s)
		}
	}
	return e
}

// rvaToOffset is libyara's elf_rva_to_offset: program headers for
// executables, section headers otherwise.
func (e *elfFile) rvaToOffset(rva uint64) (uint64, bool) {
	if e.typ == 2 { // ET_EXEC
		for _, s := range e.segs {
			if s.typ == 1 && rva >= s.vaddr && rva < s.vaddr+s.memsz { // PT_LOAD
				off := s.offset + (rva - s.vaddr)
				return off, off < uint64(len(e.data))
			}
		}
		return 0, false
	}
	for _, s := range e.secs {
		if s.typ != 0 && s.typ != 8 && rva >= s.addr && rva < s.addr+s.size {
			off := s.offset + (rva - s.addr)
			return off, off < uint64(len(e.data))
		}
	}
	return 0, false
}

// symbols reads every section of secType; found reports whether one
// exists (libyara only sets the *_entries count then).
func (e *elfFile) symbols(secType uint32) (out []value, found bool) {
	for _, s := range e.secs {
		if s.typ != secType || s.entsize == 0 || int(s.link) >= len(e.secs) {
			continue
		}
		found = true
		strtab := e.secs[s.link]
		if s.offset+s.size > uint64(len(e.data)) {
			continue
		}
		for i := uint64(0); i < min(s.size/s.entsize, maxELFEntries); i++ {
			o := int(s.offset + i*s.entsize)
			var nameOff, val, size, info, shndx uint64
			nameOff, _ = e.uint(o, 4)
			if e.is64 {
				info, _ = e.uint(o+4, 1)
				shndx, _ = e.uint(o+6, 2)
				val, _ = e.uint(o+8, 8)
				size, _ = e.uint(o+16, 8)
			} else {
				val, _ = e.uint(o+4, 4)
				size, _ = e.uint(o+8, 4)
				info, _ = e.uint(o+12, 1)
				shndx, _ = e.uint(o+14, 2)
			}
			sym := map[string]value{
				"value": vInt(int64(val)), "size": vInt(int64(size)),
				"type": vInt(int64(info & 0xf)), "bind": vInt(int64(info >> 4)),
				"shndx": vInt(int64(shndx)),
			}
			if nameOff < strtab.size {
				if n, ok := e.cstr(strtab.offset + nameOff); ok {
					sym["name"] = vStr(n)
				}
			}
			out = append(out, value{k: tyStruct, m: sym})
		}
	}
	return out, found
}

func (e *elfFile) dynamic() (out []value, found bool) {
	for _, s := range e.segs {
		if s.typ != 2 { // PT_DYNAMIC
			continue
		}
		found = true
		ent := uint64(8)
		if e.is64 {
			ent = 16
		}
		for i := uint64(0); i < min(s.filesz/ent, maxELFEntries); i++ {
			o := int(s.offset + i*ent)
			tag, ok1 := e.word(o)
			val, ok2 := e.word(o + int(ent/2))
			if !ok1 || !ok2 {
				break
			}
			out = append(out, value{k: tyStruct, m: map[string]value{"type": vInt(int64(tag)), "val": vInt(int64(val))}})
			if tag == 0 {
				break
			}
		}
		break
	}
	return out, found
}

func (e *elfFile) value() value {
	m := map[string]value{
		"type":               vInt(int64(e.typ)),
		"number_of_sections": vInt(int64(len(e.secs))),
		"number_of_segments": vInt(int64(len(e.segs))),
	}
	mach, _ := e.uint(18, 2)
	m["machine"] = vInt(int64(mach))
	if e.entry != 0 {
		if off, ok := e.rvaToOffset(e.entry); ok {
			m["entry_point"] = vInt(int64(off))
		}
	}
	m["ph_offset"] = vInt(int64(e.phoff))
	m["ph_entry_size"] = vInt(int64(e.phentsize))
	m["sh_offset"] = vInt(int64(e.shoff))
	m["sh_entry_size"] = vInt(int64(e.shentsize))
	var secs []value
	for _, s := range e.secs {
		secs = append(secs, value{k: tyStruct, m: map[string]value{
			"type": vInt(int64(s.typ)), "flags": vInt(int64(s.flags)), "address": vInt(int64(s.addr)),
			"name": vStr(s.name), "size": vInt(int64(s.size)), "offset": vInt(int64(s.offset)),
		}})
	}
	m["sections"] = value{k: tyArray, a: secs}
	var segs []value
	for _, s := range e.segs {
		segs = append(segs, value{k: tyStruct, m: map[string]value{
			"type": vInt(int64(s.typ)), "flags": vInt(int64(s.flags)), "offset": vInt(int64(s.offset)),
			"virtual_address": vInt(int64(s.vaddr)), "physical_address": vInt(int64(s.paddr)),
			"file_size": vInt(int64(s.filesz)), "memory_size": vInt(int64(s.memsz)), "alignment": vInt(int64(s.align)),
		}})
	}
	m["segments"] = value{k: tyArray, a: segs}
	for _, t := range []struct {
		name  string
		items func() ([]value, bool)
	}{
		{"dynamic", e.dynamic},
		{"symtab", func() ([]value, bool) { return e.symbols(2) }},
		{"dynsym", func() ([]value, bool) { return e.symbols(11) }},
	} {
		items, found := t.items()
		m[t.name] = value{k: tyArray, a: items}
		if found {
			count := t.name + "_entries"
			if t.name == "dynamic" {
				count = "dynamic_section_entries"
			}
			m[count] = vInt(int64(len(items)))
		}
	}
	return value{k: tyStruct, m: m}
}

func init() {
	sym := func() *schema {
		return sArray(sStruct(map[string]*schema{
			"name": sStr(), "value": sInt(), "size": sInt(), "type": sInt(), "bind": sInt(),
			"shndx": sInt(),
		}))
	}
	f := map[string]*schema{
		"type": sInt(), "machine": sInt(), "entry_point": sInt(),
		"ph_offset": sInt(), "ph_entry_size": sInt(), "sh_offset": sInt(), "sh_entry_size": sInt(),
		"number_of_sections": sInt(), "number_of_segments": sInt(),
		"sections": sArray(sStruct(map[string]*schema{
			"type": sInt(), "flags": sInt(), "address": sInt(), "name": sStr(), "size": sInt(), "offset": sInt(),
		})),
		"segments": sArray(sStruct(map[string]*schema{
			"type": sInt(), "flags": sInt(), "offset": sInt(), "virtual_address": sInt(),
			"physical_address": sInt(), "file_size": sInt(), "memory_size": sInt(), "alignment": sInt(),
		})),
		"dynamic_section_entries": sInt(),
		"dynamic":                 sArray(sStruct(map[string]*schema{"type": sInt(), "val": sInt()})),
		"symtab_entries":          sInt(),
		"symtab":                  sym(),
		"dynsym_entries":          sInt(),
		"dynsym":                  sym(),
	}
	consts := map[string]int64{
		"ET_NONE": 0, "ET_REL": 1, "ET_EXEC": 2, "ET_DYN": 3, "ET_CORE": 4,
		"EM_NONE": 0, "EM_M32": 1, "EM_SPARC": 2, "EM_386": 3, "EM_68K": 4, "EM_88K": 5, "EM_860": 7,
		"EM_MIPS": 8, "EM_MIPS_RS3_LE": 10, "EM_PPC": 20, "EM_PPC64": 21, "EM_ARM": 40, "EM_X86_64": 62,
		"EM_AARCH64": 183,
		"SHT_NULL":   0, "SHT_PROGBITS": 1, "SHT_SYMTAB": 2, "SHT_STRTAB": 3, "SHT_RELA": 4, "SHT_HASH": 5,
		"SHT_DYNAMIC": 6, "SHT_NOTE": 7, "SHT_NOBITS": 8, "SHT_REL": 9, "SHT_SHLIB": 10, "SHT_DYNSYM": 11,
		"SHF_WRITE": 1, "SHF_ALLOC": 2, "SHF_EXECINSTR": 4,
		"PT_NULL": 0, "PT_LOAD": 1, "PT_DYNAMIC": 2, "PT_INTERP": 3, "PT_NOTE": 4, "PT_SHLIB": 5,
		"PT_PHDR": 6, "PT_TLS": 7, "PT_GNU_EH_FRAME": 0x6474e550, "PT_GNU_STACK": 0x6474e551,
		"PT_GNU_RELRO": 0x6474e552, "PT_GNU_PROPERTY": 0x6474e553,
		"PF_X": 1, "PF_W": 2, "PF_R": 4,
		"DT_NULL": 0, "DT_NEEDED": 1, "DT_PLTRELSZ": 2, "DT_PLTGOT": 3, "DT_HASH": 4, "DT_STRTAB": 5,
		"DT_SYMTAB": 6, "DT_RELA": 7, "DT_RELASZ": 8, "DT_RELAENT": 9, "DT_STRSZ": 10, "DT_SYMENT": 11,
		"DT_INIT": 12, "DT_FINI": 13, "DT_SONAME": 14, "DT_RPATH": 15, "DT_SYMBOLIC": 16, "DT_REL": 17,
		"DT_RELSZ": 18, "DT_RELENT": 19, "DT_PLTREL": 20, "DT_DEBUG": 21, "DT_TEXTREL": 22, "DT_JMPREL": 23,
		"DT_BIND_NOW": 24, "DT_INIT_ARRAY": 25, "DT_FINI_ARRAY": 26, "DT_INIT_ARRAYSZ": 27,
		"DT_FINI_ARRAYSZ": 28, "DT_RUNPATH": 29, "DT_FLAGS": 30, "DT_ENCODING": 32,
		"STT_NOTYPE": 0, "STT_OBJECT": 1, "STT_FUNC": 2, "STT_SECTION": 3, "STT_FILE": 4, "STT_COMMON": 5,
		"STT_TLS": 6, "STB_LOCAL": 0, "STB_GLOBAL": 1, "STB_WEAK": 2,
		"STV_DEFAULT": 0, "STV_INTERNAL": 1, "STV_HIDDEN": 2, "STV_PROTECTED": 3,
	}
	for name, v := range consts {
		f[name] = sConst(v)
	}
	registerModule(&module{
		name:   "elf",
		schema: sStruct(f),
		load: func(sc *scanCtx) (value, any) {
			e := parseELF(sc.data)
			if e == nil {
				return value{k: tyStruct, m: map[string]value{}}, nil
			}
			return e.value(), e
		},
	})
}
