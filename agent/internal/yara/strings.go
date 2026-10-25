package yara

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"
)

// regexScanLimit bounds the length of a regex match, as libyara 4.5
// does (a greedy match is cut at this length, not dropped). Hex strings
// are not bounded.
const regexScanLimit = 1024

func compileString(s *stringDef) error {
	switch s.kind {
	case strText:
		s.lits = textVariants(s)
		return nil
	case strHex:
		lit, pattern, err := hexToRegex(s.src)
		if err != nil {
			return err
		}
		if lit != nil {
			s.lits = []litVariant{{pat: lit}}
			return nil
		}
		prog, err := compileRegex(pattern, false, true, false)
		if err != nil {
			return err
		}
		s.prog = prog
		return nil
	case strRegex:
		forms := []bool{false}
		switch {
		case s.wide && s.ascii:
			forms = []bool{false, true}
		case s.wide:
			forms = []bool{true}
		}
		// One program per form; wide and ascii are alternatives.
		var progs []*byteProg
		for _, wide := range forms {
			p, err := compileRegex(latin1(s.src), s.nocase, s.dotall, wide)
			if err != nil {
				return err
			}
			progs = append(progs, p)
		}
		s.prog = progs[0]
		if len(progs) > 1 {
			s.prog.alt = progs[1]
		}
		return nil
	}
	return errors.New("unknown string type")
}

// textVariants expands a text string into every byte pattern its
// modifiers allow.
func textVariants(s *stringDef) []litVariant {
	plain := []byte(s.src)
	type form struct {
		pat  []byte
		wide bool
	}
	var forms []form
	if s.ascii || !s.wide {
		forms = append(forms, form{plain, false})
	}
	if s.wide {
		forms = append(forms, form{widen(plain), true})
	}
	var out []litVariant
	if s.base64 || s.base64wide {
		enc := base64.StdEncoding
		if s.b64alpha != "" {
			enc = base64.NewEncoding(s.b64alpha)
		}
		for _, f := range forms {
			for _, sub := range base64Substrings(f.pat, enc) {
				if s.base64 {
					out = append(out, litVariant{pat: sub})
				}
				if s.base64wide {
					out = append(out, litVariant{pat: widen(sub), wide: true})
				}
			}
		}
		return out
	}
	for _, f := range forms {
		out = append(out, litVariant{pat: f.pat, nocase: s.nocase, xor: s.xor, wide: f.wide})
	}
	return out
}

func widen(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0)
	}
	return out
}

// base64Substrings returns the three encodings of s at each alignment,
// trimmed of the characters that depend on surrounding bytes. This is
// the same construction libyara uses.
func base64Substrings(s []byte, enc *base64.Encoding) [][]byte {
	var out [][]byte
	for i := 0; i <= 2; i++ {
		buf := make([]byte, i+len(s))
		copy(buf[i:], s)
		e := []byte(enc.EncodeToString(buf))
		front := [3]int{0, 2, 3}[i]
		back := 0
		switch len(buf) % 3 {
		case 1:
			back = 3
		case 2:
			back = 2
		}
		if front+back >= len(e) {
			continue
		}
		out = append(out, e[front:len(e)-back])
	}
	return out
}

func latin1(s string) string {
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

// hexToRegex translates a hex string body. A string of plain bytes is
// returned as a literal; anything else as an RE2 pattern over Latin-1.
func hexToRegex(body string) (lit []byte, pattern string, err error) {
	var b strings.Builder
	h := &hexParser{src: body}
	plain := true
	lit = []byte{}
	depth := 0
	tokens := 0
	lastWasJump := false
	for {
		h.skipSpace()
		if h.pos >= len(h.src) {
			break
		}
		c := h.src[h.pos]
		switch {
		case c == '(':
			h.pos++
			depth++
			plain = false
			b.WriteString("(?:")
			lastWasJump = false
		case c == ')':
			h.pos++
			depth--
			if depth < 0 {
				return nil, "", errors.New("unbalanced ')' in hex string")
			}
			b.WriteString(")")
		case c == '|':
			h.pos++
			if depth == 0 {
				return nil, "", errors.New("'|' outside alternation in hex string")
			}
			b.WriteString("|")
		case c == '[':
			if tokens == 0 {
				return nil, "", errors.New("hex string cannot start with a jump")
			}
			lo, hi, err := h.jump()
			if err != nil {
				return nil, "", err
			}
			plain = false
			writeJump(&b, lo, hi)
			lastWasJump = true
			continue
		default:
			atom, byteVal, isByte, err := h.atom()
			if err != nil {
				return nil, "", err
			}
			if isByte {
				lit = append(lit, byteVal)
			} else {
				plain = false
			}
			b.WriteString(atom)
			tokens++
			lastWasJump = false
		}
	}
	if depth != 0 {
		return nil, "", errors.New("unbalanced '(' in hex string")
	}
	if tokens == 0 {
		return nil, "", errors.New("empty hex string")
	}
	if lastWasJump {
		return nil, "", errors.New("hex string cannot end with a jump")
	}
	if plain {
		return lit, "", nil
	}
	return nil, b.String(), nil
}

type hexParser struct {
	src string
	pos int
}

func (h *hexParser) skipSpace() {
	for h.pos < len(h.src) && strings.IndexByte(" \t\r\n", h.src[h.pos]) >= 0 {
		h.pos++
	}
}

func (h *hexParser) jump() (lo, hi int, err error) {
	end := strings.IndexByte(h.src[h.pos:], ']')
	if end < 0 {
		return 0, 0, errors.New("unterminated jump in hex string")
	}
	spec := strings.ReplaceAll(h.src[h.pos+1:h.pos+end], " ", "")
	h.pos += end + 1
	parse := func(s string) (int, error) {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("invalid jump [%s]", spec)
		}
		return v, nil
	}
	if !strings.Contains(spec, "-") {
		v, err := parse(spec)
		return v, v, err
	}
	parts := strings.SplitN(spec, "-", 2)
	if parts[0] != "" {
		if lo, err = parse(parts[0]); err != nil {
			return 0, 0, err
		}
	}
	if parts[1] == "" {
		return lo, -1, nil
	}
	if hi, err = parse(parts[1]); err != nil {
		return 0, 0, err
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("invalid jump [%s]", spec)
	}
	return lo, hi, nil
}

// atom parses one hex byte, possibly with '?' nibbles or a '~' prefix.
func (h *hexParser) atom() (re string, b byte, isByte bool, err error) {
	not := false
	if h.src[h.pos] == '~' {
		not = true
		h.pos++
	}
	if h.pos+2 > len(h.src) {
		return "", 0, false, errors.New("truncated byte in hex string")
	}
	hiC, loC := h.src[h.pos], h.src[h.pos+1]
	h.pos += 2
	hi, okHi := hexVal(hiC)
	lo, okLo := hexVal(loC)
	if (!okHi && hiC != '?') || (!okLo && loC != '?') {
		return "", 0, false, fmt.Errorf("invalid byte %c%c in hex string", hiC, loC)
	}
	var set []byte
	switch {
	case okHi && okLo:
		if !not {
			return fmt.Sprintf(`\x{%02x}`, hi<<4|lo), hi<<4 | lo, true, nil
		}
		set = []byte{hi<<4 | lo}
	case !okHi && !okLo:
		if not {
			return "", 0, false, errors.New("~?? is not valid")
		}
		return `(?s:.)`, 0, false, nil
	case okHi:
		for i := byte(0); i < 16; i++ {
			set = append(set, hi<<4|i)
		}
	default:
		for i := byte(0); i < 16; i++ {
			set = append(set, i<<4|lo)
		}
	}
	var sb strings.Builder
	sb.WriteByte('[')
	if not {
		sb.WriteByte('^')
	}
	for _, c := range set {
		fmt.Fprintf(&sb, `\x{%02x}`, c)
	}
	sb.WriteByte(']')
	return sb.String(), 0, false, nil
}

// writeJump writes [lo-hi] (hi == -1: unbounded) as non-greedy
// any-byte repeats, split to stay under RE2's repeat limit of 1000.
func writeJump(b *strings.Builder, lo, hi int) {
	if hi == -1 {
		for lo > 0 {
			n := min(lo, 1000)
			fmt.Fprintf(b, `(?s:.){%d}`, n)
			lo -= n
		}
		b.WriteString(`(?s:.)*?`)
		return
	}
	for hi > 0 {
		chunkHi := min(hi, 1000)
		chunkLo := min(lo, chunkHi)
		fmt.Fprintf(b, `(?s:.){%d,%d}?`, chunkLo, chunkHi)
		lo -= chunkLo
		hi -= chunkHi
	}
}

// ─── byte-oriented regex program ────────────────────────────────────

type binst struct {
	op    syntax.InstOp
	out   uint32
	arg   uint32
	set   byteSet // bytes accepted by a rune instruction
	empty syntax.EmptyOp
}

type byteProg struct {
	insts []binst
	start uint32
	first byteSet // bytes a match can start with
	// prefix is a literal every match starts with; firstByte is the
	// only possible first byte, or -1. Both let the scan skip ahead.
	prefix    []byte
	firstByte int
	// alt is a second program tried at the same offsets (the wide form
	// of an "ascii wide" regex).
	alt *byteProg
}

type byteSet [4]uint64

func (s *byteSet) has(c byte) bool { return s[c>>6]&(1<<(c&63)) != 0 }
func (s *byteSet) add(c byte)      { s[c>>6] |= 1 << (c & 63) }

func compileRegex(pattern string, nocase, dotall, wide bool) (*byteProg, error) {
	flags := syntax.Perl
	if dotall {
		flags |= syntax.DotNL
	}
	re, err := syntax.Parse(pattern, flags)
	if err != nil {
		return nil, err
	}
	if nocase {
		re = foldASCII(re)
	}
	if wide {
		re = widenRegex(re)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, err
	}
	bp := &byteProg{start: uint32(prog.Start), insts: make([]binst, len(prog.Inst)), firstByte: -1}
	if pre, _ := prog.Prefix(); pre != "" {
		for _, r := range pre {
			if r > 255 {
				bp.prefix = nil
				break
			}
			bp.prefix = append(bp.prefix, byte(r))
		}
	}
	for i := range prog.Inst {
		in := &prog.Inst[i]
		bi := binst{op: in.Op, out: in.Out, arg: in.Arg}
		switch in.Op {
		case syntax.InstRune, syntax.InstRune1:
			// Walk the ranges directly: foldASCII leaves them unsorted,
			// which Inst.MatchRune does not allow.
			r := in.Rune
			if in.Op == syntax.InstRune1 || len(r) == 1 {
				r = []rune{r[0], r[0]}
			}
			for j := 0; j+1 < len(r); j += 2 {
				for c := max(r[j], 0); c <= min(r[j+1], 255); c++ {
					bi.set.add(byte(c))
				}
			}
			if syntax.Flags(in.Arg)&syntax.FoldCase != 0 {
				for c := 0; c < 256; c++ {
					if in.MatchRune(rune(c)) {
						bi.set.add(byte(c))
					}
				}
			}
			bi.op = syntax.InstRune
		case syntax.InstRuneAny:
			bi.set = byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
			bi.op = syntax.InstRune
		case syntax.InstRuneAnyNotNL:
			bi.set = byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
			bi.set[0] &^= 1 << '\n'
			bi.op = syntax.InstRune
		case syntax.InstEmptyWidth:
			bi.empty = syntax.EmptyOp(in.Arg)
		case syntax.InstAltMatch:
			bi.op = syntax.InstAlt
		}
		bp.insts[i] = bi
	}
	empty, first := bp.firstBytes()
	if empty {
		// libyara tries such a pattern at every offset.
		first = byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
		bp.prefix = nil
	}
	bp.first = first
	n := 0
	for c := 0; c < 256; c++ {
		if first.has(byte(c)) {
			n++
			bp.firstByte = c
		}
	}
	if n != 1 {
		bp.firstByte = -1
	}
	return bp, nil
}

// firstBytes walks the epsilon closure of the start state.
func (p *byteProg) firstBytes() (matchesEmpty bool, set byteSet) {
	seen := make([]bool, len(p.insts))
	var walk func(pc uint32)
	walk = func(pc uint32) {
		if seen[pc] {
			return
		}
		seen[pc] = true
		in := &p.insts[pc]
		switch in.op {
		case syntax.InstMatch:
			matchesEmpty = true
		case syntax.InstRune:
			for i := range set {
				set[i] |= in.set[i]
			}
		case syntax.InstAlt:
			walk(in.out)
			walk(in.arg)
		case syntax.InstNop, syntax.InstCapture, syntax.InstEmptyWidth:
			walk(in.out)
		}
	}
	walk(p.start)
	return
}

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func swapCase(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r + 32
}

// foldASCII makes letters match both cases. Unlike RE2's (?i) it does
// not fold Latin-1 letters such as À/à, matching YARA's nocase.
func foldASCII(re *syntax.Regexp) *syntax.Regexp {
	switch re.Op {
	case syntax.OpLiteral:
		var subs []*syntax.Regexp
		for _, r := range re.Rune {
			if isASCIILetter(r) {
				subs = append(subs, &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{r, r, swapCase(r), swapCase(r)}})
			} else {
				subs = append(subs, &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{r}})
			}
		}
		if len(subs) == 1 {
			return subs[0]
		}
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
	case syntax.OpCharClass:
		out := append([]rune(nil), re.Rune...)
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for _, span := range [][2]rune{{'a', 'z'}, {'A', 'Z'}} {
				a, b := max(lo, span[0]), min(hi, span[1])
				if a <= b {
					out = append(out, swapCase(a), swapCase(b))
				}
			}
		}
		return &syntax.Regexp{Op: syntax.OpCharClass, Rune: out}
	}
	for i, sub := range re.Sub {
		re.Sub[i] = foldASCII(sub)
	}
	return re
}

// widenRegex makes every matched character be followed by a NUL byte,
// the UTF-16LE form of ASCII text.
func widenRegex(re *syntax.Regexp) *syntax.Regexp {
	nul := func() *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{0}} }
	switch re.Op {
	case syntax.OpLiteral:
		var r []rune
		for _, c := range re.Rune {
			r = append(r, c, 0)
		}
		return &syntax.Regexp{Op: syntax.OpLiteral, Rune: r, Flags: re.Flags}
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: []*syntax.Regexp{re, nul()}}
	}
	for i, sub := range re.Sub {
		re.Sub[i] = widenRegex(sub)
	}
	return re
}

// queue is an ordered sparse set of program counters.
type queue struct {
	sparse []uint32
	dense  []uint32
}

func newQueue(n int) *queue { return &queue{sparse: make([]uint32, n), dense: make([]uint32, 0, n)} }

func (q *queue) contains(pc uint32) bool {
	i := q.sparse[pc]
	return int(i) < len(q.dense) && q.dense[i] == pc
}

func (q *queue) insert(pc uint32) {
	q.sparse[pc] = uint32(len(q.dense))
	q.dense = append(q.dense, pc)
}

func (q *queue) clear() { q.dense = q.dense[:0] }

// machine runs a program anchored at one offset. It is reused across
// offsets of one scan.
type machine struct {
	p            *byteProg
	clist, nlist *queue
	budget       *int64
}

func newMachine(p *byteProg, budget *int64) *machine {
	return &machine{p: p, clist: newQueue(len(p.insts)), nlist: newQueue(len(p.insts)), budget: budget}
}

func emptyFlags(data []byte, pos int) syntax.EmptyOp {
	r1, r2 := rune(-1), rune(-1)
	if pos > 0 {
		r1 = rune(data[pos-1])
	}
	if pos < len(data) {
		r2 = rune(data[pos])
	}
	return syntax.EmptyOpContext(r1, r2)
}

func (m *machine) add(q *queue, pc uint32, data []byte, pos int) {
	if q.contains(pc) {
		return
	}
	q.insert(pc)
	in := &m.p.insts[pc]
	switch in.op {
	case syntax.InstAlt:
		m.add(q, in.out, data, pos)
		m.add(q, in.arg, data, pos)
	case syntax.InstNop, syntax.InstCapture:
		m.add(q, in.out, data, pos)
	case syntax.InstEmptyWidth:
		if in.empty&^emptyFlags(data, pos) == 0 {
			m.add(q, in.out, data, pos)
		}
	}
}

// matchAt returns the end of the leftmost-first match starting at
// start, or -1. window > 0 bounds the match length. It returns -2 when
// the step budget runs out.
func (m *machine) matchAt(data []byte, start, window int) int {
	end := len(data)
	if window > 0 && start+window < end {
		end = start + window
	}
	m.clist.clear()
	m.add(m.clist, m.p.start, data, start)
	matched := -1
	for pos := start; ; pos++ {
		if len(m.clist.dense) == 0 {
			break
		}
		*m.budget -= int64(len(m.clist.dense))
		if *m.budget < 0 {
			return -2
		}
		m.nlist.clear()
		for _, pc := range m.clist.dense {
			in := &m.p.insts[pc]
			if in.op == syntax.InstMatch {
				matched = pos
				break // lower-priority threads lose
			}
			if in.op == syntax.InstRune && pos < end && in.set.has(data[pos]) {
				m.add(m.nlist, in.out, data, pos+1)
			}
		}
		m.clist, m.nlist = m.nlist, m.clist
	}
	return matched
}

// search reports whether the program matches anywhere in data (the
// "matches" operator).
func (p *byteProg) search(data []byte) bool {
	budget := int64(1 << 24)
	m := newMachine(p, &budget)
	for i := 0; i < len(data); i++ {
		if !p.first.has(data[i]) {
			continue
		}
		if r := m.matchAt(data, i, 0); r >= 0 {
			return true
		} else if r == -2 {
			return false
		}
	}
	return false
}
