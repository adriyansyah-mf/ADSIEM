// Package mlscore scores executables statically: PE files with a gradient
// boosted model trained on EMBER (ml/train.py), ELF files with heuristics
// (no public ELF dataset of that size exists). It runs inside the agent:
// features, vector and trees are computed here, nothing is sent.
package mlscore

import (
	"math"
	"sort"
	"strings"
)

// Layout of the vector; ml/vectorize.py builds the same one.
const (
	nHist, nByteEnt, nStrings, nGeneral, nHeader = 256, 256, 104, 10, 62
	nSection, nImports, nExports, nDataDirs      = 255, 1280, 128, 30
	Dim                                          = nHist + nByteEnt + nStrings + nGeneral + nHeader + nSection + nImports + nExports + nDataDirs
)

// Raw is the EMBER-shaped raw feature set of one PE file.
type Raw struct {
	Histogram   [256]float64
	ByteEntropy [256]float64
	Strings     Strings
	General     General
	Header      Header
	Section     Sections
	Imports     map[string][]string // library -> functions
	Exports     []string
	DataDirs    [15][2]float64 // size, virtual address
}

type Strings struct {
	NumStrings, AvLength, Printables, Entropy float64
	Paths, URLs, Registry, MZ                 float64
	PrintableDist                             [96]float64
}

type General struct {
	Size, VSize, HasDebug, Exports, Imports, HasRelocations float64
	HasResources, HasSignature, HasTLS, Symbols             float64
}

type Header struct {
	Timestamp          float64
	Machine            string
	Characteristics    []string
	Subsystem          string
	DllCharacteristics []string
	Magic              string
	// major/minor image, linker, os, subsystem versions; sizeof code, headers, heap commit
	Numbers [11]float64
}

type Section struct {
	Name                 string
	Size, Entropy, VSize float64
	Props                []string
}

type Sections struct {
	Entry string
	List  []Section
}

func fnv1a(s string) uint32 {
	h := uint32(0x811C9DC5)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 0x01000193
	}
	return h
}

func hashCount(dst []float64, values []string) {
	for _, v := range values {
		dst[fnv1a(v)%uint32(len(dst))]++
	}
}

func hashValue(dst []float64, keys []string, vals []float64) {
	for i, k := range keys {
		dst[fnv1a(k)%uint32(len(dst))] += vals[i]
	}
}

func norm(dst []float64, counts []float64) {
	total := 0.0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return
	}
	for i, c := range counts {
		dst[i] = c / total
	}
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Vector builds the model input.
func Vector(r *Raw) []float64 {
	v := make([]float64, Dim)
	at := 0
	take := func(n int) []float64 { s := v[at : at+n]; at += n; return s }

	norm(take(nHist), r.Histogram[:])
	norm(take(nByteEnt), r.ByteEntropy[:])

	s := take(nStrings)
	copy(s, []float64{r.Strings.NumStrings, r.Strings.AvLength, r.Strings.Printables, r.Strings.Entropy,
		r.Strings.Paths, r.Strings.URLs, r.Strings.Registry, r.Strings.MZ})
	norm(s[8:], r.Strings.PrintableDist[:])

	g := r.General
	copy(take(nGeneral), []float64{g.Size, g.VSize, g.HasDebug, g.Exports, g.Imports, g.HasRelocations,
		g.HasResources, g.HasSignature, g.HasTLS, g.Symbols})

	h := take(nHeader)
	h[0] = r.Header.Timestamp
	hashCount(h[1:11], []string{r.Header.Machine})
	hashCount(h[11:21], r.Header.Characteristics)
	hashCount(h[21:31], []string{r.Header.Subsystem})
	hashCount(h[31:41], r.Header.DllCharacteristics)
	hashCount(h[41:51], []string{r.Header.Magic})
	copy(h[51:], r.Header.Numbers[:])

	sec := take(nSection)
	secs := r.Section.List
	var zero, noName, rx, w float64
	names := make([]string, len(secs))
	sizes, ents, vsizes := make([]float64, len(secs)), make([]float64, len(secs)), make([]float64, len(secs))
	for i, x := range secs {
		if x.Size == 0 {
			zero++
		}
		if x.Name == "" {
			noName++
		}
		if has(x.Props, "MEM_READ") && has(x.Props, "MEM_EXECUTE") {
			rx++
		}
		if has(x.Props, "MEM_WRITE") {
			w++
		}
		names[i], sizes[i], ents[i], vsizes[i] = x.Name, x.Size, x.Entropy, x.VSize
	}
	copy(sec, []float64{float64(len(secs)), zero, noName, rx, w})
	// Python builds a dict name -> value: a repeated name keeps its last value
	ln, ls, le, lv := lastByName(names, sizes, ents, vsizes)
	hashValue(sec[5:55], ln, ls)
	hashValue(sec[55:105], ln, le)
	hashValue(sec[105:155], ln, lv)
	hashCount(sec[155:205], []string{r.Section.Entry})
	for _, x := range secs {
		if x.Name == r.Section.Entry {
			hashCount(sec[205:255], x.Props)
			break
		}
	}

	imp := take(nImports)
	libs := map[string]bool{}
	var funcs []string
	for lib, fs := range r.Imports {
		l := strings.ToLower(lib)
		libs[l] = true
		for _, f := range fs {
			funcs = append(funcs, l+":"+f)
		}
	}
	libList := make([]string, 0, len(libs))
	for l := range libs {
		libList = append(libList, l)
	}
	sort.Strings(libList)
	hashCount(imp[:256], libList)
	hashCount(imp[256:], funcs)

	hashCount(take(nExports), r.Exports)

	dd := take(nDataDirs)
	for i := 0; i < 15; i++ {
		dd[2*i], dd[2*i+1] = r.DataDirs[i][0], r.DataDirs[i][1]
	}
	for i, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			v[i] = 0
		}
	}
	return v
}

func lastByName(names []string, a, b, c []float64) ([]string, []float64, []float64, []float64) {
	idx := map[string]int{}
	var ln []string
	var la, lb, lc []float64
	for i, n := range names {
		if j, ok := idx[n]; ok {
			la[j], lb[j], lc[j] = a[i], b[i], c[i]
			continue
		}
		idx[n] = len(ln)
		ln = append(ln, n)
		la, lb, lc = append(la, a[i]), append(lb, b[i]), append(lc, c[i])
	}
	return ln, la, lb, lc
}
