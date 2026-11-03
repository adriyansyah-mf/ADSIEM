package yara

import (
	"regexp/syntax"
)

// The prefilter lets a scan skip strings that cannot match. Every string
// gets "atoms": 2 to 4 bytes that each of its matches must contain
// (lower-cased ASCII, so one pass over the lower-cased data serves nocase
// strings too). One pass finds the atoms present; strings with none of
// theirs present have no matches, without being searched. Strings without
// an atom (XOR strings, regexes with no required literal, single bytes)
// are always searched. Like libyara's Aho-Corasick atoms, it only removes
// work: a string that matches always has its atom in the data.

const maxAtom = 4

// atomScore rates a candidate atom: varied bytes are rare in files,
// zeros, spaces, 0xFF, NOP and INT3 runs are common.
func atomScore(a []byte) int {
	seen := map[byte]bool{}
	score := 0
	for _, c := range a {
		if !seen[c] {
			seen[c] = true
			score += 10
		}
		switch c {
		case 0x00, 0x20, 0xff, 0x90, 0xcc:
			score -= 12
		}
	}
	return score + 3*len(a)
}

// bestAtom returns the best window of at most maxAtom bytes of lit
// (already lower-cased), or nil when lit is shorter than 2 bytes.
func bestAtom(lit []byte) []byte {
	a, _ := bestAtomAt(lit)
	return a
}

// bestAtomAt also returns the window's offset in lit.
func bestAtomAt(lit []byte) ([]byte, int) {
	if len(lit) < 2 {
		return nil, 0
	}
	if len(lit) <= maxAtom {
		return lit, 0
	}
	best, at, bestScore := lit[:maxAtom], 0, -1<<30
	for i := 0; i+maxAtom <= len(lit); i++ {
		if s := atomScore(lit[i : i+maxAtom]); s > bestScore {
			best, at, bestScore = lit[i:i+maxAtom], i, s
		}
	}
	return best, at
}

func betterLit(a, b []byte) []byte {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if atomScore(bestAtom(b)) > atomScore(bestAtom(a)) {
		return b
	}
	return a
}

// requiredLit returns a literal (lower-cased) that every match of re
// contains, or nil.
func requiredLit(re *syntax.Regexp) []byte {
	switch re.Op {
	case syntax.OpLiteral:
		out := make([]byte, 0, len(re.Rune))
		for _, r := range re.Rune {
			if r > 255 {
				return nil
			}
			out = append(out, lowerByte(byte(r)))
		}
		return out
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLit(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLit(re.Sub[0])
		}
	case syntax.OpConcat:
		var best, run []byte
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				if lit := requiredLit(sub); lit != nil {
					run = append(run, lit...)
					continue
				}
			}
			best = betterLit(best, run)
			run = nil
			best = betterLit(best, requiredLit(sub))
		}
		return betterLit(best, run)
	}
	return nil
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func lowerAll(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = lowerByte(c)
	}
	return out
}

// regexAtom: the atom of a regex or hex pattern, wide when the form is,
// and the longest match the pattern allows (-1: unbounded).
func regexAtom(pattern string, wide bool) ([]byte, int) {
	re, err := syntax.Parse(pattern, syntax.Perl|syntax.DotNL)
	if err != nil {
		return nil, -1
	}
	lit := requiredLit(re)
	if wide && lit != nil {
		lit = widen(lit)
	}
	n := maxLen(re)
	if wide && n > 0 {
		n *= 2
	}
	return bestAtom(lit), n
}

// maxLen is the longest match of re in bytes (runes are bytes here), or -1.
func maxLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpQuest:
		return maxLen(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return -1
		}
		n := maxLen(re.Sub[0])
		if n < 0 {
			return -1
		}
		return n * re.Max
	case syntax.OpConcat:
		total := 0
		for _, s := range re.Sub {
			n := maxLen(s)
			if n < 0 {
				return -1
			}
			total += n
		}
		return total
	case syntax.OpAlternate:
		best := 0
		for _, s := range re.Sub {
			n := maxLen(s)
			if n < 0 {
				return -1
			}
			best = max(best, n)
		}
		return best
	}
	return -1
}

// atomsOf returns the string's atoms (any present means it may match), or
// nil when it must always be searched. For a literal string, offs[i] is
// where atom i sits in literal variant i.
func atomsOf(s *stringDef) (atoms [][]byte, offs []int) {
	switch {
	case s.lits != nil:
		for _, v := range s.lits {
			if v.xor {
				return nil, nil
			}
			a, off := bestAtomAt(lowerAll(v.pat))
			if a == nil {
				return nil, nil
			}
			atoms = append(atoms, a)
			offs = append(offs, off)
		}
	case s.kind == strHex:
		_, pattern, err := hexToRegex(s.src)
		if err != nil {
			return nil, nil
		}
		a, span := regexAtom(pattern, false)
		if a == nil {
			return nil, nil
		}
		atoms = append(atoms, a)
		s.progSpan = []int{span}
	case s.kind == strRegex:
		forms := []bool{false}
		switch {
		case s.wide && s.ascii:
			forms = []bool{false, true}
		case s.wide:
			forms = []bool{true}
		}
		for _, wide := range forms {
			a, span := regexAtom(latin1(s.src), wide)
			if a == nil {
				return nil, nil
			}
			atoms = append(atoms, a)
			// a regex match is also cut at its window
			if span < 0 || span > s.regexWindow && s.regexWindow > 0 {
				span = s.regexWindow
			}
			s.progSpan = append(s.progSpan, span)
		}
	default:
		return nil, nil
	}
	return atoms, offs
}

type prefilter struct {
	nStrings int
	always   []bool // by string id: no atom, always searched
	filter   [1 << 16 / 64]uint64
	m2       map[uint16]int32 // 2-byte atom -> atom index
	m3       map[uint32]int32
	m4       map[uint32]int32
	strsOf   [][]int32 // atom index -> string ids
}

// maxAtomHits: an atom found more often than this is "dense": its literal
// strings are searched in the whole data instead of at each hit.
const maxAtomHits = 4096

// pfScan is the prefilter's result for one scan.
type pfScan struct {
	possible []bool    // by string id
	pos      [][]int32 // by atom index: offsets of the atom (nil when dense)
	dense    []bool
}

func (r *Rules) prefilter() *prefilter {
	r.pfOnce.Do(func() { r.pf = buildPrefilter(r.rules) })
	return r.pf
}

func buildPrefilter(rules []*rule) *prefilter {
	p := &prefilter{m2: map[uint16]int32{}, m3: map[uint32]int32{}, m4: map[uint32]int32{}}
	index := map[string]int32{}
	for _, ru := range rules {
		for _, s := range ru.strs {
			s.gid = p.nStrings
			p.nStrings++
			atoms, offs := atomsOf(s)
			p.always = append(p.always, atoms == nil)
			if offs != nil {
				s.litAtom, s.litOff = make([]int32, len(atoms)), offs
				s.litLow = make([][]byte, len(s.lits))
				for i, v := range s.lits {
					s.litLow[i] = lowerAll(v.pat)
				}
			}
			for ai, a := range atoms {
				idx, ok := index[string(a)]
				if !ok {
					idx = int32(len(p.strsOf))
					index[string(a)] = idx
					p.strsOf = append(p.strsOf, nil)
					k2 := uint16(a[0]) | uint16(a[1])<<8
					p.filter[k2>>6] |= 1 << (k2 & 63)
					switch len(a) {
					case 2:
						p.m2[k2] = idx
					case 3:
						p.m3[uint32(a[0])|uint32(a[1])<<8|uint32(a[2])<<16] = idx
					default:
						p.m4[uint32(a[0])|uint32(a[1])<<8|uint32(a[2])<<16|uint32(a[3])<<24] = idx
					}
				}
				p.strsOf[idx] = append(p.strsOf[idx], int32(s.gid))
				if offs != nil {
					s.litAtom[ai] = idx
				} else {
					s.progAtom = append(s.progAtom, idx)
				}
			}
		}
	}
	return p
}

// scan finds the atoms in lowered (the lower-cased data): which strings may
// match, and where each atom is.
func (p *prefilter) scan(lowered []byte) *pfScan {
	out := make([]bool, p.nStrings)
	copy(out, p.always)
	hit := make([]bool, len(p.strsOf))
	res := &pfScan{possible: out, pos: make([][]int32, len(p.strsOf)), dense: make([]bool, len(p.strsOf))}
	mark := func(idx int32, at int) {
		hit[idx] = true
		if res.dense[idx] {
			return
		}
		if len(res.pos[idx]) >= maxAtomHits {
			res.dense[idx], res.pos[idx] = true, nil
			return
		}
		res.pos[idx] = append(res.pos[idx], int32(at))
	}
	n := len(lowered)
	for i := 0; i+1 < n; i++ {
		k2 := uint16(lowered[i]) | uint16(lowered[i+1])<<8
		if p.filter[k2>>6]&(1<<(k2&63)) == 0 {
			continue
		}
		if idx, ok := p.m2[k2]; ok {
			mark(idx, i)
		}
		if i+2 < n {
			k3 := uint32(k2) | uint32(lowered[i+2])<<16
			if idx, ok := p.m3[k3]; ok {
				mark(idx, i)
			}
			if i+3 < n {
				if idx, ok := p.m4[k3|uint32(lowered[i+3])<<24]; ok {
					mark(idx, i)
				}
			}
		}
	}
	for idx, h := range hit {
		if h {
			for _, id := range p.strsOf[idx] {
				out[id] = true
			}
		}
	}
	return res
}
