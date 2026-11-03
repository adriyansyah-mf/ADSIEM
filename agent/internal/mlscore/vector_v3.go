package mlscore

import (
	"sort"
	"strconv"
	"strings"
)

// DimV3 is the length of VectorV3 (ml/v3/vectorize.py DIM).
const DimV3 = 7 + 256 + 256 + 177 + 74 + 224 + 1282 + 129 + 34 + 33

var v3Machines = []string{"IMAGE_FILE_MACHINE_UNKNOWN", "IMAGE_FILE_MACHINE_I386", "IMAGE_FILE_MACHINE_R3000",
	"IMAGE_FILE_MACHINE_R4000", "IMAGE_FILE_MACHINE_R10000", "IMAGE_FILE_MACHINE_WCEMIPSV2",
	"IMAGE_FILE_MACHINE_ALPHA", "IMAGE_FILE_MACHINE_SH3", "IMAGE_FILE_MACHINE_SH3DSP", "IMAGE_FILE_MACHINE_SH3E",
	"IMAGE_FILE_MACHINE_SH4", "IMAGE_FILE_MACHINE_SH5", "IMAGE_FILE_MACHINE_ARM", "IMAGE_FILE_MACHINE_THUMB",
	"IMAGE_FILE_MACHINE_ARMNT", "IMAGE_FILE_MACHINE_AM33", "IMAGE_FILE_MACHINE_POWERPC",
	"IMAGE_FILE_MACHINE_POWERPCFP", "IMAGE_FILE_MACHINE_IA64", "IMAGE_FILE_MACHINE_MIPS16",
	"IMAGE_FILE_MACHINE_ALPHA64", "IMAGE_FILE_MACHINE_AXP64", "IMAGE_FILE_MACHINE_MIPSFPU",
	"IMAGE_FILE_MACHINE_MIPSFPU16", "IMAGE_FILE_MACHINE_TRICORE", "IMAGE_FILE_MACHINE_CEF",
	"IMAGE_FILE_MACHINE_EBC", "IMAGE_FILE_MACHINE_RISCV32", "IMAGE_FILE_MACHINE_RISCV64",
	"IMAGE_FILE_MACHINE_RISCV128", "IMAGE_FILE_MACHINE_LOONGARCH32", "IMAGE_FILE_MACHINE_LOONGARCH64",
	"IMAGE_FILE_MACHINE_AMD64", "IMAGE_FILE_MACHINE_M32R", "IMAGE_FILE_MACHINE_ARM64", "IMAGE_FILE_MACHINE_CEE"}

var v3Subsystems = []string{"IMAGE_SUBSYSTEM_UNKNOWN", "IMAGE_SUBSYSTEM_NATIVE", "IMAGE_SUBSYSTEM_WINDOWS_GUI",
	"IMAGE_SUBSYSTEM_WINDOWS_CUI", "IMAGE_SUBSYSTEM_OS2_CUI", "IMAGE_SUBSYSTEM_POSIX_CUI",
	"IMAGE_SUBSYSTEM_NATIVE_WINDOWS", "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", "IMAGE_SUBSYSTEM_EFI_APPLICATION",
	"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM",
	"IMAGE_SUBSYSTEM_XBOX", "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"}

var v3ImageChars = []string{"RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED", "LOCAL_SYMS_STRIPPED",
	"AGGRESIVE_WS_TRIM", "LARGE_ADDRESS_AWARE", "16BIT_MACHINE", "BYTES_REVERSED_LO", "32BIT_MACHINE",
	"DEBUG_STRIPPED", "REMOVABLE_RUN_FROM_SWAP", "NET_RUN_FROM_SWAP", "SYSTEM", "DLL", "UP_SYSTEM_ONLY",
	"BYTES_REVERSED_HI"}

var v3DllChars = []string{"HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION",
	"NO_SEH", "NO_BIND", "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE"}

var v3Dos = []string{"e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp",
	"e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"}

var v3Optional = []string{"major_image_version", "minor_image_version", "major_linker_version",
	"minor_linker_version", "major_operating_system_version", "minor_operating_system_version",
	"major_subsystem_version", "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_image",
	"sizeof_initialized_data", "sizeof_uninitialized_data", "sizeof_stack_reserve", "sizeof_stack_commit",
	"sizeof_heap_reserve", "sizeof_heap_commit", "address_of_entrypoint", "base_of_code", "image_base",
	"section_alignment", "checksum", "number_of_rvas_and_sizes"}

var v3Dirs = []string{"EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "COPYRIGHT",
	"GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

func hashInto(out []float64, items []string) {
	for _, k := range items {
		out[fnv1a(k)%uint32(len(out))]++
	}
}

func hashPairsInto(out []float64, keys []string, vals []float64) {
	for i, k := range keys {
		out[fnv1a(k)%uint32(len(out))] += vals[i]
	}
}

func normInto(out []float64, counts []int) {
	total := 0.0
	for _, c := range counts {
		total += float64(c)
	}
	if total == 0 {
		return
	}
	for i, c := range counts {
		out[i] = float64(c) / total
	}
}

func num(v any) float64 {
	switch x := v.(type) {
	case uint8:
		return float64(x)
	case uint16:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	}
	return 0
}

// VectorV3 is ml/v3/vectorize.py's vector of the raw v3 features.
func VectorV3(r *RawV3) []float64 {
	v := make([]float64, DimV3)
	at := 0
	next := func(n int) []float64 { s := v[at : at+n]; at += n; return s }

	g := next(7)
	g[0], g[1], g[2] = float64(r.General.Size), r.General.Entropy, float64(r.General.IsPE)
	for i := 0; i < 4; i++ {
		g[3+i] = float64(r.General.StartBytes[i])
	}
	normInto(next(256), r.Histogram)
	normInto(next(256), r.ByteEntropy)

	s := next(177)
	pr := float64(r.Strings.Printables)
	div := pr
	if div <= 0 {
		div = 1
	}
	s[0], s[1], s[2] = float64(r.Strings.NumStrings), r.Strings.AvLength, pr
	for i := 0; i < 96 && i < len(r.Strings.PrintableDist); i++ {
		s[3+i] = float64(r.Strings.PrintableDist[i]) / div
	}
	s[99] = r.Strings.Entropy
	for i, k := range V3StringKeys {
		s[100+i] = float64(r.Strings.Counts[k])
	}

	h := next(74)
	if r.Header != nil {
		c, o := r.Header.Coff, r.Header.Optional
		h[0], h[1], h[2] = float64(c.Timestamp), float64(c.NumberOfSections), float64(c.NumberOfSymbols)
		h[3], h[4] = float64(c.SizeOfOptionalHeader), float64(c.PointerToSymbolTable)
		h[5] = float64(max(indexOf(v3Machines, c.Machine), 0))
		sub, _ := o["subsystem"].(string)
		h[6] = float64(max(indexOf(v3Subsystems, sub), 0))
		for i, k := range v3Optional {
			h[7+i] = num(o[k])
		}
		at := 7 + len(v3Optional)
		for i, k := range v3ImageChars {
			if indexOf(c.Characteristics, k) >= 0 {
				h[at+i] = 1
			}
		}
		at += len(v3ImageChars)
		dc, _ := o["dll_characteristics"].([]string)
		for i, k := range v3DllChars {
			if indexOf(dc, k) >= 0 {
				h[at+i] = 1
			}
		}
		at += len(v3DllChars)
		for i, k := range v3Dos {
			h[at+i] = float64(r.Header.Dos[k])
		}
	}

	sec := next(224)
	if r.Section != nil {
		ss := r.Section.Sections
		ov := r.Section.Overlay
		ent := []float64{ov.Entropy, 0}
		sr := []float64{ov.SizeRatio, 0}
		vr := []float64{0}
		var zero, empty, rx, w float64
		var names []string
		var sizes, vsizes, ents []float64
		var props []string
		for _, x := range ss {
			ent = append(ent, x.Entropy)
			sr = append(sr, x.SizeRatio)
			vr = append(vr, x.VSizeRatio)
			if x.Size == 0 {
				zero++
			}
			if x.Name == "" {
				empty++
			}
			if indexOf(x.Props, "MEM_READ") >= 0 && indexOf(x.Props, "MEM_EXECUTE") >= 0 {
				rx++
			}
			if indexOf(x.Props, "MEM_WRITE") >= 0 {
				w++
			}
			names = append(names, x.Name)
			sizes, vsizes, ents = append(sizes, float64(x.Size)), append(vsizes, float64(x.VSize)), append(ents, x.Entropy)
			for _, p := range x.Props {
				props = append(props, x.Name+":"+p)
			}
		}
		mx := func(a []float64) float64 {
			m := a[0]
			for _, x := range a {
				m = max(m, x)
			}
			return m
		}
		mn := func(a []float64) float64 {
			m := a[0]
			for _, x := range a {
				m = min(m, x)
			}
			return m
		}
		copy(sec, []float64{float64(len(ss)), zero, empty, rx, w, mx(ent), mn(ent), mx(sr), mn(sr), mx(vr), mn(vr)})
		hashPairsInto(sec[11:61], names, sizes)
		hashPairsInto(sec[61:111], names, vsizes)
		hashPairsInto(sec[111:161], names, ents)
		hashInto(sec[161:211], props)
		hashInto(sec[211:221], []string{r.Section.Entry})
		sec[221], sec[222], sec[223] = float64(ov.Size), ov.SizeRatio, ov.Entropy
	}

	imp := next(1282)
	if len(r.Imports) > 0 {
		libSet := map[string]bool{}
		var funcs []string
		for lib, list := range r.Imports {
			l := strings.ToLower(lib)
			libSet[l] = true
			for _, e := range list {
				funcs = append(funcs, l+":"+e)
			}
		}
		libs := make([]string, 0, len(libSet))
		for l := range libSet {
			libs = append(libs, l)
		}
		sort.Strings(libs)
		imp[0], imp[1] = float64(len(funcs)), float64(len(libs))
		hashInto(imp[2:258], libs)
		hashInto(imp[258:1282], funcs)
	}

	exp := next(129)
	if len(r.Exports) > 0 {
		exp[0] = float64(len(r.Exports))
		hashInto(exp[1:], r.Exports)
	}

	dd := next(34)
	if len(r.DataDirs) > 0 {
		for _, d := range r.DataDirs[1:] {
			name, _ := d["name"].(string)
			if i := indexOf(v3Dirs, name); i >= 0 {
				dd[2*i], dd[2*i+1] = num(d["size"]), num(d["virtual_address"])
			}
		}
		dd[32], dd[33] = num(r.DataDirs[0]["has_relocs"]), num(r.DataDirs[0]["has_dynamic_relocs"])
	}

	rich := next(33)
	if len(r.Rich) > 0 {
		rich[0] = float64(len(r.Rich) / 2)
		var keys []string
		var vals []float64
		for i := 0; i+1 < len(r.Rich); i += 2 {
			keys = append(keys, strconv.FormatUint(uint64(r.Rich[i]), 10))
			vals = append(vals, float64(r.Rich[i+1]))
		}
		hashPairsInto(rich[1:], keys, vals)
	}
	return v
}
