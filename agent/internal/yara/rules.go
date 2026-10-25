// Package yara is a pure-Go YARA engine: it compiles rules written in the
// YARA language and scans byte buffers with them. It exists because the
// agent is built with CGO_ENABLED=0, which rules out libyara and YARA-X.
//
// Behaviour is checked against libyara by the differential tests in
// testdata/differential. Language features that are not implemented are
// compile errors, never silent mismatches; docs/operations/yara.md lists
// the supported subset.
package yara

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
)

// Source is one rule text. Each source gets its own namespace, so rule
// names only need to be unique within a source.
type Source struct {
	Namespace string
	Text      string
}

// SourceError is a compile error for one source.
type SourceError struct {
	Namespace string
	Err       error
}

func (e SourceError) Error() string { return e.Namespace + ": " + e.Err.Error() }

// Rules is a compiled, immutable rule set safe for concurrent scans.
type Rules struct {
	rules   []*rule
	maxVars int
}

// Compile compiles a single rule text.
func Compile(text string) (*Rules, error) {
	r, errs := CompileSources([]Source{{Namespace: "default", Text: text}})
	if len(errs) > 0 {
		return nil, errs[0].Err
	}
	return r, nil
}

// CompileSources compiles each source independently. A source that
// fails to compile is left out and reported; the others still load.
func CompileSources(srcs []Source) (*Rules, []SourceError) {
	out := &Rules{}
	var errs []SourceError
	for _, s := range srcs {
		rules, maxVars, err := parseSource(s.Text, s.Namespace, len(out.rules))
		if err != nil {
			errs = append(errs, SourceError{Namespace: s.Namespace, Err: err})
			continue
		}
		out.rules = append(out.rules, rules...)
		out.maxVars = max(out.maxVars, maxVars)
	}
	return out, errs
}

// Len returns the number of compiled rules.
func (r *Rules) Len() int { return len(r.rules) }

// StringMatch is one occurrence of a string.
type StringMatch struct {
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Data   []byte `json:"data"` // at most MaxMatchData bytes
}

// RuleMatch is a rule whose condition held.
type RuleMatch struct {
	Rule      string        `json:"rule"`
	Namespace string        `json:"namespace"`
	Tags      []string      `json:"tags,omitempty"`
	Meta      []Meta        `json:"meta,omitempty"`
	Strings   []StringMatch `json:"strings,omitempty"`
}

// Result of a scan. Warnings report limits that were hit; a rule may
// have been missed when a warning is present.
type Result struct {
	Matches  []RuleMatch `json:"matches"`
	Warnings []string    `json:"warnings,omitempty"`
}

const (
	// MaxMatchData is how much matched data is reported per occurrence.
	MaxMatchData = 64
	// MaxReportedMatches limits the occurrences reported per string; the
	// condition still sees all of them (up to maxMatches).
	MaxReportedMatches = 16
	maxMatches         = 100_000
	stepBudget         = 200_000_000
)

// Scan runs every rule over data.
func (r *Rules) Scan(ctx context.Context, data []byte) (Result, error) {
	sc := newScanCtx(ctx, r, data)
	var res Result
	globalFail := map[string]bool{}
	for _, ru := range r.rules {
		if ru.global && !sc.ruleResult(ru) {
			globalFail[ru.ns] = true
		}
	}
	for _, ru := range r.rules {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if globalFail[ru.ns] || ru.private || !sc.ruleResult(ru) {
			continue
		}
		m := RuleMatch{Rule: ru.name, Namespace: ru.ns, Tags: ru.tags, Meta: ru.meta}
		for _, s := range ru.strs {
			if s.private {
				continue
			}
			for i, sm := range sc.stringMatches(s) {
				if i == MaxReportedMatches {
					break
				}
				end := min(sm.off+min(sm.len, MaxMatchData), len(data))
				m.Strings = append(m.Strings, StringMatch{
					ID: "$" + s.id, Offset: int64(sm.off), Length: sm.len,
					Data: bytes.Clone(data[sm.off:end]),
				})
			}
		}
		res.Matches = append(res.Matches, m)
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	res.Warnings = sc.warnings
	return res, nil
}

// ScanFile reads a regular file of at most maxSize bytes and scans it.
func (r *Rules) ScanFile(ctx context.Context, path string, maxSize int64) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Result{}, err
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxSize {
		return Result{}, fmt.Errorf("%s is larger than %d bytes", path, maxSize)
	}
	data := make([]byte, info.Size())
	if _, err := readFull(f, data); err != nil {
		return Result{}, err
	}
	return r.Scan(ctx, data)
}

func readFull(f *os.File, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			if n == len(buf) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

type smatch struct{ off, len int }

type modData struct {
	root  value
	state any
}

type scanCtx struct {
	ctx      context.Context
	rules    *Rules
	data     []byte
	lower    []byte
	xorDiff  []byte // data[i] ^ data[i+1], for xor strings
	matches  map[*stringDef][]smatch
	ruleRes  []int8 // 0 not evaluated, 1 true, 2 false
	mods     map[*module]*modData
	vars     []value
	curStr   []*stringDef // for..of stack
	budget   int64
	warnings []string
}

func newScanCtx(ctx context.Context, r *Rules, data []byte) *scanCtx {
	return &scanCtx{
		ctx: ctx, rules: r, data: data,
		matches: map[*stringDef][]smatch{},
		ruleRes: make([]int8, len(r.rules)),
		mods:    map[*module]*modData{},
		vars:    make([]value, r.maxVars),
	}
}

func (sc *scanCtx) warnf(format string, args ...any) {
	sc.warnings = append(sc.warnings, fmt.Sprintf(format, args...))
}

func (sc *scanCtx) ruleResult(r *rule) bool {
	switch sc.ruleRes[r.idx] {
	case 1:
		return true
	case 2:
		return false
	}
	v := sc.eval(r.cond)
	ok, defined := truth(v)
	res := ok && defined
	sc.ruleRes[r.idx] = 2
	if res {
		sc.ruleRes[r.idx] = 1
	}
	return res
}

func (sc *scanCtx) module(m *module) *modData {
	md, ok := sc.mods[m]
	if !ok {
		root, state := m.load(sc)
		md = &modData{root: root, state: state}
		sc.mods[m] = md
	}
	return md
}

func (sc *scanCtx) lowered() []byte {
	if sc.lower == nil {
		sc.lower = bytes.Clone(sc.data)
		for i, c := range sc.lower {
			if c >= 'A' && c <= 'Z' {
				sc.lower[i] = c + 32
			}
		}
	}
	return sc.lower
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func fullwordOK(data []byte, off, n int, wide bool) bool {
	if wide {
		if off >= 2 && data[off-1] == 0 && isAlnum(data[off-2]) {
			return false
		}
		if end := off + n; end+1 < len(data) && isAlnum(data[end]) && data[end+1] == 0 {
			return false
		}
		return true
	}
	if off >= 1 && isAlnum(data[off-1]) {
		return false
	}
	if end := off + n; end < len(data) && isAlnum(data[end]) {
		return false
	}
	return true
}

func lowerASCII(b []byte) []byte {
	out := bytes.Clone(b)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return out
}

// stringMatches finds (once per scan) every occurrence of s.
func (sc *scanCtx) stringMatches(s *stringDef) []smatch {
	if ms, ok := sc.matches[s]; ok {
		return ms
	}
	var ms []smatch
	full := false
	addMatch := func(off, n int, wide bool) bool {
		if s.fullword && !fullwordOK(sc.data, off, n, wide) {
			return true
		}
		if len(ms) >= maxMatches {
			full = true
			return false
		}
		ms = append(ms, smatch{off, n})
		return true
	}
	if s.lits != nil {
		for _, v := range s.lits {
			switch {
			case v.xor:
				sc.findXor(v, s, addMatch)
			case v.nocase:
				findAll(sc.lowered(), lowerASCII(v.pat), func(off int) bool { return addMatch(off, len(v.pat), v.wide) })
			default:
				findAll(sc.data, v.pat, func(off int) bool { return addMatch(off, len(v.pat), v.wide) })
			}
		}
	} else {
		sc.budget = stepBudget
		exhausted := false
		for p, wide := s.prog, s.wide && !s.ascii; p != nil; p, wide = p.alt, true {
			m := newMachine(p, &sc.budget)
			for i := 0; i < len(sc.data) && !exhausted; i++ {
				if i = p.nextCandidate(sc.data, i); i < 0 {
					break
				}
				end := m.matchAt(sc.data, i, s.regexWindow)
				if end == -2 {
					exhausted = true
					break
				}
				if end >= i && !addMatch(i, end-i, wide) {
					break
				}
			}
		}
		if exhausted {
			sc.warnf("string $%s is too slow to match; scan stopped early, matches may be missing", s.id)
		}
	}
	if full {
		sc.warnf("string $%s has more than %d matches; the rest were dropped", s.id, maxMatches)
	}
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].off < ms[j].off })
	// Two variants can hit the same offset (e.g. a pattern and its
	// base64 form); YARA records one match per offset.
	out := ms[:0]
	for i, m := range ms {
		if i > 0 && m.off == ms[i-1].off {
			continue
		}
		if s.fixed == fixedYes && int64(m.off) != s.fixedOff {
			continue
		}
		out = append(out, m)
	}
	sc.matches[s] = out
	return out
}

// findAll calls fn for every (overlapping) occurrence of pat.
func findAll(data, pat []byte, fn func(off int) bool) {
	pos := 0
	for pos <= len(data)-len(pat) {
		i := bytes.Index(data[pos:], pat)
		if i < 0 {
			return
		}
		if !fn(pos + i) {
			return
		}
		pos += i + 1
	}
}

// findXor finds pat XORed with any single-byte key in the string's
// range. XOR with one key leaves the XOR of neighbouring bytes
// unchanged, so the pattern's neighbour differences are searched in
// the data's (computed once per scan) with bytes.Index.
func (sc *scanCtx) findXor(v litVariant, s *stringDef, add func(off, n int, wide bool) bool) {
	data, pat := sc.data, v.pat
	inRange := func(i int) bool {
		k := int(data[i] ^ pat[0])
		return k >= s.xorMin && k <= s.xorMax
	}
	if len(pat) == 1 {
		for i := range data {
			if inRange(i) && !add(i, 1, v.wide) {
				return
			}
		}
		return
	}
	if sc.xorDiff == nil && len(data) > 1 {
		sc.xorDiff = make([]byte, len(data)-1)
		for i := range sc.xorDiff {
			sc.xorDiff[i] = data[i] ^ data[i+1]
		}
	}
	want := make([]byte, len(pat)-1)
	for j := range want {
		want[j] = pat[j] ^ pat[j+1]
	}
	findAll(sc.xorDiff, want, func(i int) bool {
		if !inRange(i) {
			return true
		}
		return add(i, len(pat), v.wide)
	})
}

// nextCandidate returns the first offset >= i where p may match.
func (p *byteProg) nextCandidate(data []byte, i int) int {
	switch {
	case len(p.prefix) > 0:
		j := bytes.Index(data[i:], p.prefix)
		if j < 0 {
			return -1
		}
		return i + j
	case p.firstByte >= 0:
		j := bytes.IndexByte(data[i:], byte(p.firstByte))
		if j < 0 {
			return -1
		}
		return i + j
	}
	for ; i < len(data); i++ {
		if p.first.has(data[i]) {
			return i
		}
	}
	return -1
}
