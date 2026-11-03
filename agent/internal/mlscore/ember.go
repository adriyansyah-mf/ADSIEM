package mlscore

// EMBER returns the raw features in EMBER's JSON shape (ember/features.py),
// for comparing with EMBER's own extractor and with ml/vectorize.py.
func (r *Raw) EMBER() map[string]any {
	secs := make([]map[string]any, 0, len(r.Section.List))
	for _, s := range r.Section.List {
		props := s.Props
		if props == nil {
			props = []string{}
		}
		secs = append(secs, map[string]any{"name": s.Name, "size": s.Size, "entropy": s.Entropy, "vsize": s.VSize,
			"props": props})
	}
	dd := make([]map[string]any, 15)
	for i := range dd {
		dd[i] = map[string]any{"size": r.DataDirs[i][0], "virtual_address": r.DataDirs[i][1]}
	}
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	h := r.Header
	return map[string]any{
		"histogram":   r.Histogram[:],
		"byteentropy": r.ByteEntropy[:],
		"strings": map[string]any{
			"numstrings": r.Strings.NumStrings, "avlength": r.Strings.AvLength, "printables": r.Strings.Printables,
			"entropy": r.Strings.Entropy, "paths": r.Strings.Paths, "urls": r.Strings.URLs,
			"registry": r.Strings.Registry, "MZ": r.Strings.MZ, "printabledist": r.Strings.PrintableDist[:],
		},
		"general": map[string]any{
			"size": r.General.Size, "vsize": r.General.VSize, "has_debug": r.General.HasDebug,
			"exports": r.General.Exports, "imports": r.General.Imports, "has_relocations": r.General.HasRelocations,
			"has_resources": r.General.HasResources, "has_signature": r.General.HasSignature,
			"has_tls": r.General.HasTLS, "symbols": r.General.Symbols,
		},
		"header": map[string]any{
			"coff": map[string]any{"timestamp": h.Timestamp, "machine": h.Machine,
				"characteristics": nonNil(h.Characteristics)},
			"optional": map[string]any{
				"subsystem": h.Subsystem, "dll_characteristics": nonNil(h.DllCharacteristics), "magic": h.Magic,
				"major_image_version": h.Numbers[0], "minor_image_version": h.Numbers[1],
				"major_linker_version": h.Numbers[2], "minor_linker_version": h.Numbers[3],
				"major_operating_system_version": h.Numbers[4], "minor_operating_system_version": h.Numbers[5],
				"major_subsystem_version": h.Numbers[6], "minor_subsystem_version": h.Numbers[7],
				"sizeof_code": h.Numbers[8], "sizeof_headers": h.Numbers[9], "sizeof_heap_commit": h.Numbers[10],
			},
		},
		"section":         map[string]any{"entry": r.Section.Entry, "sections": secs},
		"imports":         r.Imports,
		"exports":         nonNil(r.Exports),
		"datadirectories": dd,
	}
}
